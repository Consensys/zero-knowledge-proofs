#![feature(rustc_private)]

extern crate rustc;
use rustc::util::sha2::{Digest,Sha256};
use std::u8;

use self::Test::*;

enum Test {
    Valid,
    AndInsteadOfXor
}

fn main() {
    println!("valid: ");
    gen(Valid);
    println!("using AND instead of XOR: ");
    gen(AndInsteadOfXor);
}

fn gen(test: Test) {
    let r2: Vec<u8> = {
        let mut hash = Sha256::new();
        hash.input("SCIPR".as_ref());
        hash.result_bytes()
    };
    let x: Vec<u8> = {
        let mut hash = Sha256::new();
        hash.input("LAB".as_ref());
        hash.result_bytes()
    };
    let r1 = {
        let mut v = vec![];
        for (a, b) in r2.iter().zip(x.iter()) {
            if let AndInsteadOfXor = test {
                v.push(a & b);
            } else {
                v.push(a ^ b);
            }
        }

        v
    };

    let h1: Vec<u8> = {
        let mut hash = Sha256::new();
        hash.input(&r1);
        hash.result_bytes()
    };

    let h2: Vec<u8> = {
        let mut hash = Sha256::new();
        hash.input(&r2);
        hash.result_bytes()
    };

    print!("h1_bv = int_list_to_bits("); into_bin(&h1);
    print!("h2_bv = int_list_to_bits("); into_bin(&h2);
    print!("x_bv = int_list_to_bits("); into_bin(&x);
    print!("r1_bv = int_list_to_bits("); into_bin(&r1);
    print!("r2_bv = int_list_to_bits("); into_bin(&r2);
}

fn into_bin(a: &Vec<u8>) {
    let mut first = true;
    print!("{{");
    for a in a.iter() {
        print!("{}{}",
                {if !first { ", " } else {first = false; ""}},
                a
                );
    }
    println!("}}, 8);");
}
