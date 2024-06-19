import numpy as np

dilatation_factor = 16
polynomial_degree = dilatation_factor

PRECISION_BITS = 28
UPPER_BITS = 9
scale = pow(2.0, PRECISION_BITS)

polynomial_multiplications = int(np.ceil(np.log2(polynomial_degree))) + 1
n_polynomials = 2
matrix_multiplications = 3

depth = matrix_multiplications + polynomial_multiplications * n_polynomials

poly_modulus_degree = 16384

moduli = [PRECISION_BITS + UPPER_BITS] + (depth) * [PRECISION_BITS] + [PRECISION_BITS + UPPER_BITS]