use proc_macro2::TokenStream;
use quote::{format_ident, quote};
use std::iter;
use syn::{Attribute, Data, DataEnum, DataStruct, DeriveInput, Fields, Lit, Meta, MetaNameValue};

#[cfg(target_family = "unix")]
const OS_LINE_ENDING: &str = "\n";
#[cfg(target_family = "windows")]
const OS_LINE_ENDING: &str = "\r\n";

pub fn derive(input: TokenStream) -> TokenStream {
    let ast: DeriveInput = match syn::parse2(input) {
        Ok(ast) => ast,
        Err(error) => return error.into_compile_error(),
    };

    let docs = match &ast.data {
        Data::Struct(DataStruct {
            fields: Fields::Named(fields),
            ..
        }) => fields
            .named
            .iter()
            .filter_map(|field| {
                field
                    .ident
                    .clone()
                    .zip(Some(collect_docs(field.attrs.iter())))
            })
            .collect::<Vec<_>>(),
        Data::Struct(_) => Vec::default(),
        Data::Enum(DataEnum { variants, .. }) => variants
            .iter()
            .map(|variant| {
                (
                    format_ident!("{}", variant.ident.to_string().to_lowercase()),
                    collect_docs(variant.attrs.iter()),
                )
            })
            .collect::<Vec<_>>(),
        Data::Union(_) => {
            return syn::Error::new_spanned(
                &ast,
                "`RuntimeDoc` has to be used only with structs or enums",
            )
            .into_compile_error();
        }
    };

    let funcs = iter::once((None, collect_docs(ast.attrs.iter())))
        .chain(docs.into_iter().map(|(ident, doc)| (Some(ident), doc)))
        .fold(quote!(), |stream, (name, doc)| {
            if doc.is_empty() {
                return stream;
            }

            let name = name.map_or_else(|| format_ident!("doc"), |x| format_ident!("doc_{x}"));
            quote! {
                #stream
                #[doc = "Return this item's documentation."]
                #[must_use]
                pub fn #name() -> &'static str {
                    #doc
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

fn collect_docs<'a, I>(attrs: I) -> String
where
    I: Iterator<Item = &'a Attribute>,
{
    attrs
        .filter_map(|attr| attr.parse_meta().ok())
        .filter(|meta| meta.path().is_ident("doc"))
        .filter_map(|meta| match meta {
            Meta::NameValue(MetaNameValue {
                lit: Lit::Str(lit), ..
            }) => Some(lit.value().trim().to_string()),
            _ => None,
        })
        .filter(|doc| !doc.is_empty())
        .collect::<Vec<_>>()
        .join(OS_LINE_ENDING)
}

#[cfg(test)]
mod tests {
    use super::{derive, OS_LINE_ENDING};
    use quote::quote;

    #[test]
    fn unions_emit_compile_errors() {
        let output = derive(quote!(union Foo { x: usize }));
        assert_eq!(
            output.to_string(),
            quote!(compile_error! {
                "`RuntimeDoc` has to be used only with structs or enums"
            })
            .to_string()
        );
    }

    #[test]
    fn malformed_input_emits_a_compile_error() {
        let output = derive(quote!(struct));
        assert_eq!(
            output.to_string(),
            quote!(compile_error! { "unexpected end of input, expected identifier" }).to_string()
        );
    }

    #[test]
    fn trims_docs_and_ignores_non_text_attributes() {
        let output = derive(quote! {
            #[doc(hidden)]
            #[doc = " \t "]
            #[repr(C)]
            #[doc = " first "]
            #[doc = ""]
            #[doc = "\tsecond\t"]
            struct Foo;
        });
        let doc = ["first", "second"].join(OS_LINE_ENDING);
        assert_eq!(
            output.to_string(),
            quote! {
                impl Foo {
                    #[doc = "Return this item's documentation."]
                    #[must_use]
                    pub fn doc() -> &'static str {
                        #doc
                    }
                }
            }
            .to_string()
        );
    }
}
