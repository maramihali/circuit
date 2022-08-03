use ark_bls12_377::{Fq, Fr, G1Projective};
use ark_ec::ProjectiveCurve;
use ark_ff::{BigInteger, PrimeField, UniformRand};
use ark_nonnative_field::NonNativeFieldVar;
use ark_r1cs_std::{
  alloc::AllocVar, fields::fp::FpVar, R1CSVar, ToBitsGadget, ToConstraintFieldGadget,
};
use ark_relations::{ns, r1cs::ConstraintSystem};
use ark_sponge::{
  constraints::{AbsorbGadget, CryptographicSpongeVar},
  poseidon::{constraints::PoseidonSpongeVar, PoseidonSponge},
  CryptographicSponge,
};

use crate::preimage_circuit::get_bls12377_fq_params;

#[test]
fn test() {
  let params = get_bls12377_fq_params();

  let mut rng = ark_std::test_rng();

  let scalar = Fr::rand(&mut rng);

  let mut sponge = PoseidonSponge::new(&params);
  sponge.absorb(&scalar.into_repr().to_bits_le());
  let hash = sponge.squeeze_field_elements::<Fr>(1).remove(0);

  let cs = ConstraintSystem::<Fq>::new_ref();

  let nonnative_scalar_var =
    NonNativeFieldVar::<Fr, Fq>::new_input(ns!(cs.clone(), "nonnative"), || Ok(scalar)).unwrap();

  let mut sponge_var = PoseidonSpongeVar::new(cs.clone(), &params);
  sponge_var
    .absorb(&nonnative_scalar_var.to_bits_le().unwrap())
    .unwrap();

  let hash_var = sponge_var
    .squeeze_nonnative_field_elements::<Fr>(1)
    .unwrap()
    .0
    .remove(0);

  assert_eq!(hash, hash_var.value().unwrap());
}
