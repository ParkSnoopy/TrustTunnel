//! Regression tests for runtime documentation on structs.

use macros::RuntimeDoc;

#[test]
fn slashed() {
    /// Trololo
    #[derive(RuntimeDoc)]
    struct Foo {
        /// Haha
        pub x: u32,
    }

    assert_eq!(Foo::doc(), "Trololo");
    assert_eq!(Foo::doc_x(), "Haha");
    assert_eq!(Foo { x: 42 }.x, 42);
}

#[test]
fn doc_attr() {
    #[doc = "Trololo"]
    #[derive(RuntimeDoc)]
    struct Foo {
        #[doc = "Haha"]
        pub x: u32,
    }

    assert_eq!(Foo::doc(), "Trololo");
    assert_eq!(Foo::doc_x(), "Haha");
    assert_eq!(Foo { x: 42 }.x, 42);
}

#[test]
fn mixed() {
    /// - How much watch?
    #[doc = "- Six watch"]
    #[derive(RuntimeDoc)]
    struct Foo {
        /// - Such much?
        #[doc = "- For whom how"]
        pub x: u32,
    }

    assert_eq!(
        Foo::doc(),
        r"- How much watch?
- Six watch"
    );
    assert_eq!(
        Foo::doc_x(),
        r"- Such much?
- For whom how"
    );
    assert_eq!(Foo { x: 42 }.x, 42);
}
