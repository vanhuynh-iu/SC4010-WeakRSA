from key_generation import generate_close_prime_key
from fermat_attack import fermat_attack
from private_key_recovery import recover_private_key

key = generate_close_prime_key(bits = 2048, gap_bits = 525)
n = key["n"]
e = key["e"]

print(f"Public key generated, n bit length: {n.bit_length()}")

message = "Meet after breakfast, attack at dawn"

message_bytes = message.encode("utf-8")
message_int = int.from_bytes(message_bytes, byteorder="big")

print(f"Original message: {message}")

ciphertext = pow(message_int, e, n)
print(f"Ciphertext: {ciphertext}")

result = fermat_attack(n, max_iterations= 100000000)

if result is None:
    print("Fermat attack failed")
    exit()

p_found, q_found, iterations = result

print(f"Fermat attack succeeded, iterations: {iterations}")

d_found = recover_private_key(p_found, q_found, e)
recovered_int = pow(ciphertext, d_found, n)
recovered_bytes = recovered_int.to_bytes((recovered_int.bit_length()+7)//8, byteorder="big")
recovered_messge = recovered_bytes.decode("utf-8")

print(f"Recovered msg: {recovered_messge}")