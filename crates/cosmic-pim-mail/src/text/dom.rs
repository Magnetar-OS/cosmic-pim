// Copyright 2026 Dominikos Pritis
// SPDX-License-Identifier: MPL-2.0

//! The tree html5ever builds for [`extract`](super::extract), holding what the
//! walk reads.
//!
//! html5ever decides what the bytes mean; it does not keep the result. It
//! calls a [`TreeSink`] — make an element, put this under that, move those
//! children over there — and whatever implements the sink is the tree. This is
//! that implementation, and the only one this crate parses through. It is the
//! same tree, node for node, that `scraper` built here before it: the walk's
//! output did not change when the dependency did.
//!
//! # An arena, not pointers
//!
//! Every node lives in one `Vec` and is named by its index, so dropping the
//! tree is dropping a `Vec` — not a recursion as deep as the markup, which in
//! hostile mail is as deep as the sender likes.
//!
//! # What is kept
//!
//! Elements with their names and attributes, text, and comments with their
//! text: a comment carrying prose is counted as hidden content. A
//! `<template>`'s contents go to a [`Data::Fragment`] that is the template's
//! first child, which is where `scraper` put them — so a walk that skips the
//! fragment skips them, and a search through a subtree still finds their text.
//! Doctypes and processing instructions keep their place and nothing else.
//!
//! The parser's question whether a `MathML` `annotation-xml` element takes
//! HTML content is answered "no", as `scraper` answered it.
//!
//! # Never panics
//!
//! The sink is driven by a parser fed arbitrary input, so no call may panic
//! whatever the parser asks: a node moved while it still has a parent is
//! detached first, and a request the tree cannot honour — insert before a node
//! that is nowhere — is ignored rather than asserted.

use std::borrow::Cow;
use std::cell::RefCell;

use html5ever::interface::{ElementFlags, NodeOrText, QuirksMode, TreeSink};
use html5ever::tendril::StrTendril;
use html5ever::{Attribute, ExpandedName, LocalName, Namespace, QualName};

/// A node's place in the arena.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(super) struct Id(usize);

/// What a node is.
#[derive(Debug)]
pub(super) enum Data {
    /// The document.
    Root,
    /// A `<template>`'s contents, as its first child.
    Fragment,
    Element {
        name: QualName,
        attrs: Vec<Attribute>,
    },
    Text(StrTendril),
    Comment(StrTendril),
    /// A doctype or processing instruction: a place among its siblings.
    Other,
}

#[derive(Debug)]
struct Node {
    parent: Option<Id>,
    children: Vec<Id>,
    data: Data,
}

/// A parsed document.
#[derive(Debug)]
pub(super) struct Dom {
    nodes: Vec<Node>,
}

impl Default for Dom {
    /// An empty document.
    fn default() -> Self {
        Self {
            nodes: vec![Node {
                parent: None,
                children: Vec::new(),
                data: Data::Root,
            }],
        }
    }
}

impl Dom {
    /// The document node, which every tree has.
    pub(super) const DOCUMENT: Id = Id(0);

    pub(super) fn data(&self, id: Id) -> &Data {
        &self.nodes[id.0].data
    }

    pub(super) fn children(&self, id: Id) -> &[Id] {
        &self.nodes[id.0].children
    }

    fn create(&mut self, data: Data) -> Id {
        let id = Id(self.nodes.len());
        self.nodes.push(Node {
            parent: None,
            children: Vec::new(),
            data,
        });
        id
    }

    /// Where a node sits among its parent's children, if it has a parent.
    fn position(&self, id: Id) -> Option<(Id, usize)> {
        let parent = self.nodes[id.0].parent?;
        let index = self.nodes[parent.0]
            .children
            .iter()
            .position(|child| *child == id)?;
        Some((parent, index))
    }

    fn detach(&mut self, id: Id) {
        if let Some((parent, index)) = self.position(id) {
            self.nodes[parent.0].children.remove(index);
        }
        self.nodes[id.0].parent = None;
    }

    /// Puts a node, or text, among `parent`'s children at `index`.
    ///
    /// Text arriving next to text joins it: the parser hands characters over
    /// in whatever pieces its input came in, and one run in the source is one
    /// text node in the tree.
    fn insert(&mut self, parent: Id, index: usize, child: NodeOrText<Id>) {
        let node = match child {
            NodeOrText::AppendText(text) => {
                let before = index
                    .checked_sub(1)
                    .and_then(|before| self.nodes[parent.0].children.get(before).copied());
                if let Some(before) = before
                    && let Data::Text(existing) = &mut self.nodes[before.0].data
                {
                    existing.push_tendril(&text);
                    return;
                }
                self.create(Data::Text(text))
            }
            NodeOrText::AppendNode(node) => node,
        };
        self.nodes[node.0].parent = Some(parent);
        self.nodes[parent.0].children.insert(index, node);
    }

    fn append(&mut self, parent: Id, child: NodeOrText<Id>) {
        if let NodeOrText::AppendNode(node) = &child {
            if *node == parent {
                return;
            }
            self.detach(*node);
        }
        let end = self.nodes[parent.0].children.len();
        self.insert(parent, end, child);
    }

    fn append_before(&mut self, sibling: Id, child: NodeOrText<Id>) {
        if let NodeOrText::AppendNode(node) = &child {
            if *node == sibling {
                return;
            }
            self.detach(*node);
        }
        // Looked up after the detach, which moves the sibling down one when
        // the node came from earlier under the same parent.
        if let Some((parent, index)) = self.position(sibling) {
            self.insert(parent, index, child);
        }
    }
}

/// What the parser holds a node by: its place in the arena, and its name.
///
/// The parser asks for element names constantly — every block-level start tag
/// walks its stack of open elements looking for a `<p>` to close — so the name
/// rides along and the question never opens the tree. An element's name never
/// changes, so the copy cannot go stale; a node that is not an element carries
/// the empty name, which matches nothing the parser looks for.
#[derive(Debug, Clone)]
pub(super) struct Handle {
    id: Id,
    ns: Namespace,
    local: LocalName,
}

impl Handle {
    fn unnamed(id: Id) -> Self {
        Self {
            id,
            ns: Namespace::default(),
            local: LocalName::default(),
        }
    }
}

/// A node or text to insert, by arena index rather than by handle.
fn by_id(child: NodeOrText<Handle>) -> NodeOrText<Id> {
    match child {
        NodeOrText::AppendNode(handle) => NodeOrText::AppendNode(handle.id),
        NodeOrText::AppendText(text) => NodeOrText::AppendText(text),
    }
}

/// The [`TreeSink`] html5ever builds a [`Dom`] through.
///
/// The trait takes `&self` throughout, so the tree sits in a cell; each call
/// opens it, does its one thing and closes it, and none calls another with it
/// open.
#[derive(Debug, Default)]
pub(super) struct Sink {
    dom: RefCell<Dom>,
}

impl TreeSink for Sink {
    type Handle = Handle;
    type Output = Dom;
    type ElemName<'a> = ExpandedName<'a>;

    fn finish(self) -> Dom {
        self.dom.into_inner()
    }

    /// Recoveries are the parser's business; what they produced is the tree.
    fn parse_error(&self, _msg: Cow<'static, str>) {}

    fn get_document(&self) -> Handle {
        Handle::unnamed(Dom::DOCUMENT)
    }

    fn elem_name<'a>(&'a self, target: &'a Handle) -> ExpandedName<'a> {
        ExpandedName {
            ns: &target.ns,
            local: &target.local,
        }
    }

    fn create_element(&self, name: QualName, attrs: Vec<Attribute>, flags: ElementFlags) -> Handle {
        let mut dom = self.dom.borrow_mut();
        let (ns, local) = (name.ns.clone(), name.local.clone());
        let id = dom.create(Data::Element { name, attrs });
        if flags.template {
            let contents = dom.create(Data::Fragment);
            dom.append(id, NodeOrText::AppendNode(contents));
        }
        Handle { id, ns, local }
    }

    fn create_comment(&self, text: StrTendril) -> Handle {
        Handle::unnamed(self.dom.borrow_mut().create(Data::Comment(text)))
    }

    fn create_pi(&self, _target: StrTendril, _data: StrTendril) -> Handle {
        Handle::unnamed(self.dom.borrow_mut().create(Data::Other))
    }

    fn append(&self, parent: &Handle, child: NodeOrText<Handle>) {
        self.dom.borrow_mut().append(parent.id, by_id(child));
    }

    fn append_before_sibling(&self, sibling: &Handle, child: NodeOrText<Handle>) {
        self.dom
            .borrow_mut()
            .append_before(sibling.id, by_id(child));
    }

    /// Foster parenting: content that may not sit in a table goes before the
    /// table when the table is in the tree, and otherwise into the element
    /// that was open before it.
    fn append_based_on_parent_node(
        &self,
        element: &Handle,
        prev_element: &Handle,
        child: NodeOrText<Handle>,
    ) {
        let mut dom = self.dom.borrow_mut();
        if dom.nodes[element.id.0].parent.is_some() {
            dom.append_before(element.id, by_id(child));
        } else {
            dom.append(prev_element.id, by_id(child));
        }
    }

    fn append_doctype_to_document(
        &self,
        _name: StrTendril,
        _public_id: StrTendril,
        _system_id: StrTendril,
    ) {
        let mut dom = self.dom.borrow_mut();
        let doctype = dom.create(Data::Other);
        dom.append(Dom::DOCUMENT, NodeOrText::AppendNode(doctype));
    }

    /// A `<template>`'s fragment. Asked of any other node — which the parser
    /// does not do — the answer is a fresh fragment attached to nothing, so
    /// what is put there is simply not in the document.
    fn get_template_contents(&self, target: &Handle) -> Handle {
        let mut dom = self.dom.borrow_mut();
        if let Some(&first) = dom.nodes[target.id.0].children.first()
            && matches!(dom.nodes[first.0].data, Data::Fragment)
        {
            return Handle::unnamed(first);
        }
        Handle::unnamed(dom.create(Data::Fragment))
    }

    fn same_node(&self, x: &Handle, y: &Handle) -> bool {
        x.id == y.id
    }

    /// Quirks mode changes how the parser builds the tree, which it tracks
    /// itself; nothing read from the tree afterwards depends on it.
    fn set_quirks_mode(&self, _mode: QuirksMode) {}

    fn add_attrs_if_missing(&self, target: &Handle, attrs: Vec<Attribute>) {
        let mut dom = self.dom.borrow_mut();
        let Data::Element {
            attrs: existing, ..
        } = &mut dom.nodes[target.id.0].data
        else {
            return;
        };
        for attr in attrs {
            if !existing.iter().any(|have| have.name == attr.name) {
                existing.push(attr);
            }
        }
    }

    fn remove_from_parent(&self, target: &Handle) {
        self.dom.borrow_mut().detach(target.id);
    }

    fn reparent_children(&self, node: &Handle, new_parent: &Handle) {
        if node.id == new_parent.id {
            return;
        }
        let mut dom = self.dom.borrow_mut();
        let children = std::mem::take(&mut dom.nodes[node.id.0].children);
        for child in &children {
            dom.nodes[child.0].parent = Some(new_parent.id);
        }
        dom.nodes[new_parent.id.0].children.extend(children);
    }
}

#[cfg(test)]
mod tests {
    use html5ever::interface::create_element;
    use html5ever::tendril::TendrilSink;
    use html5ever::{local_name, ns};

    use super::*;

    fn build(html: &str) -> Dom {
        html5ever::parse_document(Sink::default(), html5ever::ParseOpts::default()).one(html)
    }

    /// The tree, one node a line, two spaces a level.
    fn tree(html: &str) -> String {
        fn write(dom: &Dom, id: Id, depth: usize, out: &mut String) {
            for child in dom.children(id) {
                let line = match dom.data(*child) {
                    Data::Element { name, .. } => format!("<{}>", name.local),
                    Data::Text(text) => format!("{:?}", &**text),
                    Data::Comment(text) => format!("<!--{text}-->"),
                    Data::Fragment => "#fragment".to_owned(),
                    Data::Other => "<!>".to_owned(),
                    Data::Root => "#root".to_owned(),
                };
                out.push_str(&"  ".repeat(depth));
                out.push_str(&line);
                out.push('\n');
                write(dom, *child, depth + 1, out);
            }
        }
        let mut out = String::new();
        write(&build(html), Dom::DOCUMENT, 0, &mut out);
        out
    }

    #[test]
    fn content_that_may_not_sit_in_a_table_is_put_before_it_and_text_joins() {
        // Foster parenting, and the two runs of text it moves before the
        // table become one text node.
        assert_eq!(
            tree("<!doctype html><table>a<tr>b<td>c</table><!--x-->"),
            "<!>\n<html>\n  <head>\n  <body>\n    \"ab\"\n    <table>\n      <tbody>\n        \
             <tr>\n          <td>\n            \"c\"\n    <!--x-->\n"
        );
    }

    #[test]
    fn a_templates_contents_are_its_first_child_fragment() {
        assert_eq!(
            tree("<template>Hello</template>"),
            "<html>\n  <head>\n    <template>\n      #fragment\n        \"Hello\"\n  <body>\n"
        );
    }

    #[test]
    fn a_repeated_body_tag_adds_only_the_attributes_that_are_missing() {
        let dom = build("<body a=1><body a=2 b=3>");
        let html = dom.children(Dom::DOCUMENT)[0];
        let body = dom.children(html)[1];
        let Data::Element { attrs, .. } = dom.data(body) else {
            panic!("not an element");
        };
        let attrs: Vec<_> = attrs
            .iter()
            .map(|a| format!("{}={}", a.name.local, a.value))
            .collect();
        assert_eq!(attrs, ["a=1", "b=3"]);
    }

    #[test]
    fn a_tree_nested_deeper_than_any_stack_is_dropped_without_recursion() {
        const DEPTH: usize = 50_000;
        std::thread::Builder::new()
            .stack_size(256 * 1024)
            .spawn(|| drop(build(&"<span>".repeat(DEPTH))))
            .expect("a thread")
            .join()
            .expect("neither the build nor the drop overflowed");
    }

    fn element(sink: &Sink, name: LocalName) -> Handle {
        create_element(sink, QualName::new(None, ns!(html), name), Vec::new())
    }

    fn node(handle: &Handle) -> NodeOrText<Handle> {
        NodeOrText::AppendNode(handle.clone())
    }

    /// The parser detaches a node before it moves it, and asks for a
    /// template's contents only of a template. The sink is fed by a parser
    /// fed anything at all, so it holds up when those promises are not kept.
    #[test]
    fn calls_the_parser_does_not_make_are_absorbed_not_asserted() {
        let sink = Sink::default();
        let document = sink.get_document();
        let (first, second, third) = (
            element(&sink, local_name!("div")),
            element(&sink, local_name!("p")),
            element(&sink, local_name!("span")),
        );
        sink.append(&document, node(&first));
        sink.append(&document, node(&second));

        // Appending a node that is already somewhere moves it.
        sink.append(&first, node(&third));
        sink.append(&second, node(&third));

        // Moving a node before a later sibling under the same parent keeps
        // it before that sibling.
        sink.append_before_sibling(&second, node(&first));

        // Inserting before a node that is nowhere does nothing, and neither
        // does putting a node inside or beside itself.
        let nowhere = element(&sink, local_name!("em"));
        sink.append_before_sibling(&nowhere, node(&element(&sink, local_name!("i"))));
        sink.append(&second, node(&second));
        sink.append_before_sibling(&second, node(&second));
        sink.reparent_children(&second, &second);

        // Only an element has a name, and only a template has contents.
        assert_eq!(*sink.elem_name(&document).local, LocalName::default());
        let contents = sink.get_template_contents(&first);
        sink.append(&contents, NodeOrText::AppendText("lost".into()));

        let dom = sink.finish();
        assert_eq!(dom.children(Dom::DOCUMENT), [first.id, second.id]);
        assert_eq!(dom.children(first.id), []);
        assert_eq!(dom.children(second.id), [third.id]);
    }
}
