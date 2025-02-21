use anyhow::{Context, Result};
use heck::ToShoutySnakeCase;

use rosenpass_ciphers::subtle::either_hash::EitherShakeOrBlake;
use rosenpass_ciphers::subtle::incorrect_hmac_blake2b::Blake2bCore;
use rosenpass_ciphers::subtle::keyed_shake256::SHAKE256Core;
use rosenpass_ciphers::{hash_domain::HashDomain, KEY_LEN};

/// Recursively calculate a concrete hash value for an API message type
fn calculate_hash_value(hd: HashDomain, values: &[&str]) -> Result<[u8; KEY_LEN]> {
    match values.split_first() {
        Some((head, tail)) => calculate_hash_value(hd.mix(head.as_bytes())?, tail),
        None => Ok(hd.into_value()),
    }
}

/// Print a hash literal for pasting into the Rosenpass source code
fn print_literal(path: &[&str], shake_or_blake: EitherShakeOrBlake) -> Result<()> {
    let val = calculate_hash_value(HashDomain::zero(shake_or_blake), path)?;
    let (last, prefix) = path.split_last().context("developer error!")?;
    let var_name = last.to_shouty_snake_case();

    print!("// hash domain hash of: ");
    for n in prefix.iter() {
        print!("{n} -> ");
    }
    println!("{last}");

    let c = hex::encode(val)
        .chars()
        .collect::<Vec<char>>()
        .chunks_exact(4)
        .map(|chunk| chunk.iter().collect::<String>())
        .collect::<Vec<_>>();
    println!("const {var_name} : RawMsgType = RawMsgType::from_le_bytes(hex!(\"{} {} {} {}    {} {} {} {}\"));",
        c[0], c[1], c[2], c[3], c[4], c[5], c[6], c[7]);

    Ok(())
}

/// Tree of domain separators where each leaf represents
/// an API message ID
#[derive(Debug, Clone)]
enum Tree {
    Branch(String, Vec<Tree>),
    Leaf(String),
}

impl Tree {
    fn name(&self) -> &str {
        match self {
            Self::Branch(name, _) => name,
            Self::Leaf(name) => name,
        }
    }

    fn gen_code_inner(&self, prefix: &[&str], shake_or_blake: EitherShakeOrBlake) -> Result<()> {
        let mut path = prefix.to_owned();
        path.push(self.name());

        match self {
            Self::Branch(_, ref children) => {
                for c in children.iter() {
                    c.gen_code_inner(&path, shake_or_blake.clone())?
                }
            }
            Self::Leaf(_) => print_literal(&path, shake_or_blake)?,
        };

        Ok(())
    }

    fn gen_code(&self, shake_or_blake: EitherShakeOrBlake) -> Result<()> {
        self.gen_code_inner(&[], shake_or_blake)
    }
}

/// Helper for generating hash-based message IDs for the IPC API
fn main() -> Result<()> {
    fn print_IPC_API_info(shake_or_blake: EitherShakeOrBlake, name: String) -> Result<()> {
        let tree = Tree::Branch(
            format!("Rosenpass IPC API {}", name).to_owned(),
            vec![Tree::Branch(
                "Rosenpass Protocol Server".to_owned(),
                vec![
                    Tree::Leaf("Ping Request".to_owned()),
                    Tree::Leaf("Ping Response".to_owned()),
                    Tree::Leaf("Supply Keypair Request".to_owned()),
                    Tree::Leaf("Supply Keypair Response".to_owned()),
                    Tree::Leaf("Add Listen Socket Request".to_owned()),
                    Tree::Leaf("Add Listen Socket Response".to_owned()),
                    Tree::Leaf("Add Psk Broker Request".to_owned()),
                    Tree::Leaf("Add Psk Broker Response".to_owned()),
                ],
            )],
        );

        println!("type RawMsgType = u128;");
        println!();
        tree.gen_code(shake_or_blake)
    }

    print_IPC_API_info(
        EitherShakeOrBlake::Left(SHAKE256Core),
        " (SHAKE256)".to_owned(),
    )?;
    print_IPC_API_info(
        EitherShakeOrBlake::Right(Blake2bCore),
        " (Blake2b)".to_owned(),
    )
}
