use proc_macro2::TokenStream;
use quote::{format_ident, quote};
use syn::{Data, DataStruct, DeriveInput, Fields};

pub fn derive(input: TokenStream) -> TokenStream {
    let ast: DeriveInput = match syn::parse2(input) {
        Ok(ast) => ast,
        Err(error) => return error.into_compile_error(),
    };

    let fields = match &ast.data {
        Data::Struct(DataStruct {
            fields: Fields::Named(fields),
            ..
        }) => fields
            .named
            .iter()
            .filter_map(|field| field.ident.as_ref().zip(Some(&field.ty)))
            .collect::<Vec<_>>(),
        _ => {
            return syn::Error::new_spanned(&ast, "`Getter` has to be used only with structs")
                .into_compile_error();
        }
    };

    let funcs = fields.into_iter().fold(quote!(), |stream, (name, ty)| {
        let fn_name = format_ident!("get_{name}");
        quote! {
            #stream
            #[doc = "Borrow this field."]
            #[must_use]
            pub fn #fn_name(&self) -> &#ty {
                &self.#name
            }
        }
    });

    let name = format_ident!("{}", ast.ident);
    quote! {
        impl #name {
            #funcs
        }
    }
}

#[cfg(test)]
mod tests {
    use super::derive;
    use quote::quote;

    #[test]
    fn unsupported_items_emit_compile_errors() {
        for input in [
            quote!(
                enum Foo {
                    Bar,
                }
            ),
            quote!(union Foo { x: usize }),
            quote!(
                struct Foo(usize);
            ),
            quote!(
                struct Foo;
            ),
        ] {
            let output = derive(input);
            assert_eq!(
                output.to_string(),
                quote!(compile_error! {
                    "`Getter` has to be used only with structs"
                })
                .to_string()
            );
        }
    }

    #[test]
    fn malformed_input_emits_a_compile_error() {
        let output = derive(quote!(struct));
        assert_eq!(
            output.to_string(),
            quote!(compile_error! { "unexpected end of input, expected identifier" }).to_string()
        );
    }
}
