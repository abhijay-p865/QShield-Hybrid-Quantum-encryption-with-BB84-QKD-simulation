import random
from typing import Dict, List, Optional
from dataclasses import dataclass
import hashlib
import math
from utils import bits_to_bytes

@dataclass
class NoiseParameters:
    eta: float = 0.85
    dark_count_prob: float = 0.001
    misalignment_prob: float = 0.01

def random_bits(n: int) -> List[int]:
    return [random.randint(0, 1) for _ in range(n)]

def binary_entropy(e):
    if e == 0 or e == 1:
        return 0.0
    else:
        return ((-e*math.log(e, 2) - (1-e)*math.log(1-e, 2)))
    
        
def random_bases(n: int) -> List[str]:
    return [random.choice(["+", "x"]) for _ in range(n)]

def parity(block):
    return sum(block) % 2

def find_and_fix_error(alice_block, bob_block, start_index, depth=0):
    if len(alice_block) != len(bob_block):
        raise ValueError("alice_block and bob_block must be the same length")
    if not alice_block:
        raise ValueError("blocks must not be empty")
    if depth > 50:
        raise ValueError("Error correction exceeded maximum recursion depth.")

    if len(alice_block) == 1:
        return start_index

    mid = len(alice_block) // 2
    alice_left = alice_block[:mid]
    bob_left = bob_block[:mid]

    if parity(alice_left) != parity(bob_left):
        return find_and_fix_error(alice_left, bob_left, start_index, depth + 1)

    alice_right = alice_block[mid:]
    bob_right = bob_block[mid:]
    return find_and_fix_error(alice_right, bob_right, start_index + mid, depth + 1)


def bob_measure_bit(prepared_bit: int, prepared_basis: str, bob_basis: str, noise: NoiseParameters):
    """Bob gets exact bit on basis match, random bit on mismatch."""
    loss = random.random()
    dark_count = random.random()
    if loss>noise.eta:
        if dark_count<noise.dark_count_prob:
            return random.randint(0,1)
        return None

    misalignment = random.random()
    if misalignment<noise.misalignment_prob:
        return random.randint(0,1)

    if bob_basis == prepared_basis:
        return prepared_bit
    return random.randint(0, 1)


def eve_intercept_and_resend(alice_bit: int, alice_basis: str, noise: NoiseParameters) -> tuple[int, str]:
    """
    Eve chooses a random basis, measures, then resends her result in her basis.
    This can disturb the state when Eve basis != Alice basis.
    """
    eve_basis = random.choice(["+", "x"])
    if eve_basis == alice_basis:
        eve_bit = alice_bit
    else:
        eve_bit = random.randint(0, 1)
    return eve_bit, eve_basis


def sift_keys(alice_bits: List[Optional[int]], bob_bits: List[Optional[int]], alice_bases: List[str], bob_bases: List[str]) -> Dict[str, List[int]]:
    sifted_indices = [i for i, (a, b) in enumerate(zip(alice_bases, bob_bases)) if ((a == b) and (bob_bits[i] is not None))]
    alice_sifted = [alice_bits[i] for i in sifted_indices]
    bob_sifted = [bob_bits[i] for i in sifted_indices]
    return {
        "indices": sifted_indices,
        "alice_sifted": alice_sifted,
        "bob_sifted": bob_sifted,
    }

def privacy_amplify(key_bits: List[int], qber: float):
    if len(key_bits) < 256:
        raise ValueError("Insufficient key material for privacy amplification")
    secure_bits = int(len(key_bits) * (1 - binary_entropy(qber)))
    key_bytes = bits_to_bytes(key_bits)
    digest = hashlib.sha256(key_bytes).digest()
    return digest[0:secure_bits//8]

def reconcile_keys(alice_sifted: List[int], bob_sifted: List[int]):
    bob_reconciled = bob_sifted.copy()
    block_size = 16
    for i in range(0, len(alice_sifted), block_size):
        alice_block = alice_sifted[i:i+block_size]
        bob_block = bob_reconciled[i:i + block_size]
        alice_parity = parity(alice_block)
        bob_parity = parity(bob_block)
        if alice_parity == bob_parity:
            continue
        else:
            error_index = find_and_fix_error(alice_block, bob_block, i)
            bob_reconciled[error_index] ^=1

    return bob_reconciled

def calculate_qber(alice_sifted: List[int], bob_sifted: List[int], sample_indices: List[int]) -> float:
    """Compute mismatch rate on a caller-provided sample."""
    if not sample_indices:
        return 0.0
    mismatches = sum(1 for idx in sample_indices if alice_sifted[idx] != bob_sifted[idx])
    return mismatches / len(sample_indices)

def simulate_bb84(num_photons: int = 1000, eve_present: bool = False, debug: bool = False, noise: NoiseParameters = None) -> Dict[str, object]:

    if num_photons < 1000:
        raise ValueError("Number of photons must be at least 1000")

    if noise is None:
        noise = NoiseParameters()

    alice_bits = random_bits(num_photons)
    alice_bases = random_bases(num_photons)
    bob_bases = random_bases(num_photons)
    bob_bits = []

    for i in range(num_photons):
        tx_bit = alice_bits[i]
        tx_basis = alice_bases[i]

        if eve_present:
            (tx_bit, _eve_basis) = eve_intercept_and_resend(alice_bit=tx_bit, alice_basis=tx_basis, noise=noise)
            
        tx_bit = bob_measure_bit(tx_bit, tx_basis, bob_bases[i], noise)
        bob_bits.append(tx_bit)

    detected = sum(1 for bit in bob_bits if bit is not None)
    photon_yield = detected / len(bob_bits) if bob_bits else 0.0

    sifted = sift_keys(alice_bits, bob_bits, alice_bases, bob_bases)
    alice_sifted = sifted["alice_sifted"]
    bob_sifted = sifted["bob_sifted"]

    n_sifted = len(alice_sifted)
    sample_size = int(0.2 * n_sifted)
    sample_indices = random.sample(range(n_sifted), k=sample_size) if sample_size > 0 else []
    qber = calculate_qber(alice_sifted, bob_sifted, sample_indices)
    
    sample_set = set(sample_indices)
    alice_reconciliation = [b for i, b in enumerate(alice_sifted) if i not in sample_set]
    bob_reconciliation = [b for i, b in enumerate(bob_sifted) if i not in sample_set]

    bob_reconciled = reconcile_keys(alice_reconciliation, bob_reconciliation)

    alice_final_key = privacy_amplify(alice_reconciliation, qber)
    bob_final_key = privacy_amplify(bob_reconciled, qber)

    channel_clean = qber < 0.11

    if debug:
        print(f"Photon yield:        {photon_yield:.2%}")
        print(f"Sifted bits:         {n_sifted}")
        print(f"QBER:                {qber:.4f}")
        print(f"Channel clean:       {channel_clean}")
        print(f"Key length (Alice):  {len(alice_final_key)} bytes")
        print(f"Key length (Bob):    {len(bob_final_key)} bytes")

    return {
        "alice_bits": alice_bits,
        "alice_bases": alice_bases,
        "bob_bases": bob_bases,
        "bob_bits": bob_bits,
        "sifted_indices": sifted["indices"],
        "alice_sifted": alice_sifted,
        "bob_sifted": bob_sifted,
        "qber_sample_indices": sample_indices,
        "qber": qber,
        "sifted_bits": n_sifted,
        "channel_clean": channel_clean,
        "photon_yield": photon_yield,
        "bob_reconciled": bob_reconciled,
        "alice_final_key": alice_final_key,
        "bob_final_key": bob_final_key,
        "noise_parameters": {
            "eta": noise.eta,
            "dark_count_prob": noise.dark_count_prob,
            "misalignment_prob": noise.misalignment_prob,
        },
        "eve_present": eve_present,
        "debug": debug,
    }