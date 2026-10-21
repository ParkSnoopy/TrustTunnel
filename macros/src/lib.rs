//! Derive macros for field getters and runtime access to documentation.

mod getter;
mod rt_doc;

use proc_macro::TokenStream;

/// Collect docs for each identifier of the struct or enum and generate
/// static methods to get the docs in runtime.
///
/// Unsupported items produce a compile error rather than panicking.
///
/// ```
/// use macros::RuntimeDoc;
///
/// /// Trololo
/// #[derive(RuntimeDoc)]
/// enum Foo1 {
///     /// Haha
///     Bar,
///     /// Hehe
///     Baz,
/// }
///
/// // Is equivalent to
/// /// Trololo
/// enum Foo2 {
///     /// Haha
///     Bar,
///     /// Hehe
///     Baz,
/// }
///
/// impl Foo2 {
///     pub fn doc() -> &'static str {
///         "Trololo"
///     }
///     pub fn doc_bar() -> &'static str {
///         "Haha"
///     }
///     pub fn doc_baz() -> &'static str {
///         "Hehe"
///     }
/// }
///
/// assert_eq!(Foo1::doc(), "Trololo");
/// assert_eq!(Foo1::doc_bar(), "Haha");
/// assert_eq!(Foo1::doc_baz(), "Hehe");
/// ```
#[proc_macro_derive(RuntimeDoc)]
pub fn parse_rt_doc(input: TokenStream) -> TokenStream {
    rt_doc::derive(input.into()).into()
}

/// Generate getters for each field of the struct.
///
/// Only named-field structs are supported; other items produce a compile error.
///
/// ```
/// use macros::Getter;
///
/// #[derive(Getter)]
/// struct Foo1 {
///     x: usize,
///     y: String,
/// }
///
/// // Is equivalent to
/// struct Foo2 {
///     x: usize,
///     y: String,
/// }
///
/// impl Foo2 {
///     pub fn get_x(&self) -> &usize {
///         &self.x
///     }
///     pub fn get_y(&self) -> &String {
///         &self.y
///     }
/// }
///
/// assert_eq!(Foo1 { x: 42, y: Default::default() }.get_x(), &42);
/// ```
#[proc_macro_derive(Getter)]
pub fn parse_getter(input: TokenStream) -> TokenStream {
    getter::derive(input.into()).into()
}
