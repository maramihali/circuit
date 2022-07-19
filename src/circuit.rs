use crate::parameters::*;
use ark_bls12_377::{constraints::G1Var, Fq, G1Projective};
use ark_bw6_761::BW6_761 as P;
use ark_crypto_primitives::{CircuitSpecificSetupSNARK, SNARK};
use ark_ec::ProjectiveCurve;
use ark_ff::PrimeField;
use ark_groth16::Groth16;
use ark_r1cs_std::{fields::fp::FpVar, groups::CurveVar, prelude::*};
use ark_relations::{
  ns,
  r1cs::{ConstraintSynthesizer, ConstraintSystem, ConstraintSystemRef, SynthesisError},
};
use ark_sponge::poseidon::PoseidonParameters;
use ark_sponge::{
  constraints::CryptographicSpongeVar,
  poseidon::{constraints::PoseidonSpongeVar, PoseidonSponge},
  CryptographicSponge,
};
use std::str::FromStr;

use ark_std::UniformRand;

#[derive(Clone)]
pub struct PreimageVerification {
  pub params: PoseidonParameters<Fq>,

  // The private witness
  pub point: G1Projective,

  // The public input
  pub hash: Fq,
}

impl ConstraintSynthesizer<Fq> for PreimageVerification {
  fn generate_constraints(self, cs: ConstraintSystemRef<Fq>) -> Result<(), SynthesisError> {
    let mut sponge_var = PoseidonSpongeVar::new(cs.clone(), &self.params);

    let exp_hash_var =
      FpVar::<Fq>::new_input(ns!(cs.clone(), "hash"), || Ok(self.hash.clone())).unwrap();

    let point_var =
      G1Var::new_witness(ns!(cs.clone(), "point"), || Ok(self.point.clone())).unwrap();

    sponge_var.absorb(&point_var).unwrap();

    let hash_var = sponge_var.squeeze_field_elements(1).unwrap().remove(0);

    hash_var.enforce_equal(&exp_hash_var)?;

    Ok(())
  }
}

// copyright: https://github.com/nikkolasg/ark-dkg/blob/main/src/poseidon.rs
pub fn get_bls12377_fq_params() -> PoseidonParameters<Fq> {
  let arks = P1["ark"]
    .members()
    .map(|ark| {
      ark
        .members()
        .map(|v| Fq::from_str(v.as_str().unwrap()).unwrap())
        .collect::<Vec<_>>()
    })
    .collect::<Vec<_>>();
  let mds = P1["mds"]
    .members()
    .map(|m| {
      m.members()
        .map(|v| Fq::from_str(v.as_str().unwrap()).unwrap())
        .collect::<Vec<_>>()
    })
    .collect::<Vec<_>>();
  PoseidonParameters::new(
    P1["full_rounds"].as_u32().unwrap(),
    P1["partial_rounds"].as_u32().unwrap(),
    P1["alpha"].as_u64().unwrap(),
    mds,
    arks,
  )
}

pub fn prove(point: G1Projective) {
  let params = get_bls12377_fq_params();

  let mut rng = ark_std::test_rng();

  let cs = ConstraintSystem::<Fq>::new_ref();

  let mut sponge = PoseidonSponge::new(&params);
  sponge.absorb(&point.into_affine());
  let hash = sponge.squeeze_field_elements::<Fq>(1).remove(0);

  let mut sponge_var = PoseidonSpongeVar::new(cs.clone(), &params);

  let exp_hash_var = FpVar::<Fq>::new_input(ns!(cs.clone(), "hash"), || Ok(hash.clone())).unwrap();

  let point_var = G1Var::new_witness(ns!(cs.clone(), "point"), || Ok(point.clone())).unwrap();

  sponge_var.absorb(&point_var).unwrap();
  let hash_var = sponge_var.squeeze_field_elements(1).unwrap().remove(0);
}

#[test]
fn preimage_constraints_correctness() {
  let params = get_bls12377_fq_params();

  let mut rng = ark_std::test_rng();

  let point = G1Projective::rand(&mut rng);
  let mut sponge = PoseidonSponge::new(&params);
  sponge.absorb(&point.into_affine());

  let hash = sponge.squeeze_field_elements::<Fq>(1).remove(0);

  let circuit = PreimageVerification {
    params,
    point,
    hash,
  };
  let cs = ConstraintSystem::<Fq>::new_ref();

  circuit.generate_constraints(cs.clone()).unwrap();

  let is_satisfied = cs.is_satisfied().unwrap();
  if !is_satisfied {
    // find the offending constraint
    println!("{:?}", cs.which_is_unsatisfied());
  }
  assert!(is_satisfied);
}

#[test]
fn with_groth_16() {
  let params = get_bls12377_fq_params();

  let mut rng = ark_std::test_rng();

  let point = G1Projective::rand(&mut rng);
  let mut sponge = PoseidonSponge::new(&params);
  sponge.absorb(&point.into_affine());

  let hash = sponge.squeeze_field_elements::<Fq>(1).remove(0);

  let circuit = PreimageVerification {
    params,
    point,
    hash,
  };

  let (pk, vk) = Groth16::<P>::setup(circuit.clone(), &mut rng).unwrap();

  let proof = Groth16::prove(&pk, circuit.clone(), &mut rng).unwrap();

  let is_verified = Groth16::verify(&vk, &[hash], &proof).unwrap();

  assert!(is_verified);
}
