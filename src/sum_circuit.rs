use ark_bls12_377::Fr as TF;
use ark_bw6_761::Fr as BF;
use ark_ff::{BigInteger, PrimeField};
use ark_nonnative_field::{AllocatedNonNativeFieldVar, NonNativeFieldVar};
use ark_r1cs_std::{
  alloc::AllocVar, fields::fp::FpVar, prelude::EqGadget, R1CSVar, ToBitsGadget, ToBytesGadget,
};
use ark_relations::{
  ns,
  r1cs::{ConstraintSynthesizer, ConstraintSystem, ConstraintSystemRef, Result},
};
use ark_sponge::Absorb;
pub struct SumVerification {
  // Private witnesses
  pub a: TF,
  pub b: TF,

  // Public input
  pub sum: BF,
}

impl ConstraintSynthesizer<BF> for SumVerification {
  fn generate_constraints(self, cs: ConstraintSystemRef<BF>) -> Result<()> {
    let exp_sum_var =
      FpVar::<BF>::new_input(ns!(cs.clone(), "sum"), || Ok((self.sum.clone()))).unwrap();

    let a_var =
      NonNativeFieldVar::<TF, BF>::new_witness(ns!(cs.clone(), "a"), || Ok((self.a.clone())))
        .unwrap();
    let b_var =
      NonNativeFieldVar::<TF, BF>::new_witness(ns!(cs.clone(), "b"), || Ok(self.b.clone()))
        .unwrap();

    let sum_var = &a_var + &b_var;

    // compare bit by bit

    let mut bits_scalar_nonnative = sum_var.to_bits_le().unwrap();
    let mut bits_scalar_var = exp_sum_var.to_bits_le().unwrap();

    for (var, nonnative) in bits_scalar_var
      .iter()
      .take(TF::size_in_bits())
      .zip(bits_scalar_nonnative.iter())
    {
      var.enforce_equal(nonnative).unwrap()
    }

    // compare the underlying field elements

    let sum_var_in_tf = sum_var.value().unwrap();
    let sum_var_in_bf =
      BF::from_le_bytes_mod_order(sum_var_in_tf.into_repr().to_bytes_le().as_slice());

    assert_eq!(exp_sum_var.value().unwrap(), sum_var_in_bf);

    Ok(())
  }
}

#[test]
fn sum_correctnes() {
  let a = TF::from(4);
  let b = TF::from(8);
  let sum = BF::from(12);

  let circuit = SumVerification { a, b, sum };

  let cs = ConstraintSystem::<BF>::new_ref();

  circuit.generate_constraints(cs.clone()).unwrap();

  let is_satisfied = cs.is_satisfied().unwrap();
  if !is_satisfied {
    // find the offending constraint
    println!("{:?}", cs.which_is_unsatisfied());
  }
}
