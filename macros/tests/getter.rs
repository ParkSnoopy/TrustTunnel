//! Regression tests for generated field getters.

use macros::{Getter, RuntimeDoc};

/// A public derive target whose generated methods must satisfy documentation lints.
#[derive(Debug, Clone, Copy, Getter, RuntimeDoc)]
pub struct PublicTarget {
    /// The value exposed by the generated getter.
    value: usize,
}

#[test]
fn public_generated_methods_satisfy_documentation_lints() {
    let target = PublicTarget { value: 42 };
    assert_eq!(target.get_value(), &42);
    assert_eq!(
        PublicTarget::doc_value(),
        "The value exposed by the generated getter."
    );
}

#[test]
fn test() {
    #[derive(Getter)]
    struct Foo {
        x: usize,
    }

    assert_eq!(Foo { x: 42 }.get_x(), &42);
}

#[test]
fn borrows_non_copy_fields() {
    #[derive(Getter)]
    struct Foo {
        text: String,
        number: usize,
    }

    let foo = Foo {
        text: String::from("borrowed"),
        number: 42,
    };
    assert_eq!(foo.get_text(), "borrowed");
    assert!(std::ptr::eq(foo.get_text(), std::ptr::from_ref(&foo.text)));
    assert_eq!(foo.get_number(), &42);
}
