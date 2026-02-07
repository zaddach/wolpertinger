extern crate proc_macro;
use proc_macro::TokenStream;
use quote::quote;
use syn::{parse_macro_input, ItemFn, MetaNameValue};
use syn::punctuated::Punctuated;
use syn::token::Comma;
use syn::parse::Parser;

/// Attribute macro `export(dll = "dllname", name = "fname")`
/// `name` is optional; if omitted the function's identifier is used.
#[proc_macro_attribute]
pub fn export(attr: TokenStream, item: TokenStream) -> TokenStream {
    // Parse arguments as a list of name-value pairs: dll = "..", name = ".."
    let parser = Punctuated::<MetaNameValue, Comma>::parse_terminated;
    let args: Punctuated<MetaNameValue, Comma> = match parser.parse(attr.clone().into()) {
        Ok(v) => v,
        Err(e) => return e.to_compile_error().into(),
    };

    let mut dll_name: Option<String> = None;
    let mut name_override: Option<String> = None;

    for nv in args.iter() {
        if let Some(ident) = nv.path.get_ident() {
            if let syn::Expr::Lit(expr_lit) = &nv.value {
                if let syn::Lit::Str(s) = &expr_lit.lit {
                    match ident.to_string().as_str() {
                        "dll" => dll_name = Some(s.value()),
                        "name" => name_override = Some(s.value()),
                        _ => {}
                    }
                }
            }
        }
    }

    let dll_name = match dll_name {
        Some(v) => v,
        None => return syn::Error::new_spanned(proc_macro2::TokenStream::from(attr), "missing `dll = \"...\"` argument").to_compile_error().into(),
    };

    let input_fn = parse_macro_input!(item as ItemFn);
    let fn_ident = input_fn.sig.ident.clone();

    // Use override if provided, otherwise the function name
    let func_name = match name_override {
        Some(n) => n,
        None => fn_ident.to_string(),
    };

    let dll_lit = syn::LitStr::new(&dll_name, proc_macro2::Span::call_site());
    let func_lit = syn::LitStr::new(&func_name, proc_macro2::Span::call_site());
    let expanded = quote! {
        #input_fn

        inventory::submit! {
            crate::ExportedFunction {
                dll: #dll_lit,
                function: #func_lit,
                pointer: #fn_ident,
            }
        }
    };

    TokenStream::from(expanded)
}
