import seal

import numpy as np
import sys

sys.path.insert(0, 'cryptotree')

from concurrent.futures import ProcessPoolExecutor
import seal
from tqdm import tqdm

from tree import SigmoidTreeMaker, TanhTreeMaker


dilatation_factor = 16
polynomial_degree = dilatation_factor

sigmoid_tree_maker = SigmoidTreeMaker(use_polynomial=True,
                                dilatation_factor=dilatation_factor, polynomial_degree=polynomial_degree)

tanh_tree_maker = TanhTreeMaker(use_polynomial=True,
                                dilatation_factor=dilatation_factor, polynomial_degree=polynomial_degree)

tree_maker = sigmoid_tree_maker

dilatation_factor = 16
degree = dilatation_factor

PRECISION_BITS = 28
UPPER_BITS = 9

polynomial_multiplications = int(np.ceil(np.log2(degree))) + 1
n_polynomials = 2
matrix_multiplications = 3

depth = matrix_multiplications + polynomial_multiplications * n_polynomials

poly_modulus_degree = 16384

moduli = [PRECISION_BITS + UPPER_BITS] + (depth) * [PRECISION_BITS] + [PRECISION_BITS + UPPER_BITS]



from seal_helper import create_seal_globals, append_globals_to_builtins
import builtins

create_seal_globals(globals(), poly_modulus_degree, moduli, PRECISION_BITS, use_symmetric_key=False)
append_globals_to_builtins(globals(), builtins)


from cryptoTree import HomomorphicNeuralRandomForest, HomomorphicTreeEvaluator, HomomorphicTreeFeaturizer
from polynomials import polyeval_tree
import pickle
import torch
model = pickle.load(open("setup\model.pkl" , "rb"))
h_rf = HomomorphicNeuralRandomForest(model)

tree_evaluator = HomomorphicTreeEvaluator.from_model(h_rf, tree_maker.coeffs, 
                                                polyeval_tree, evaluator, encoder, relin_keys, galois_keys, 
                                                scale)

homomorphic_featurizer = HomomorphicTreeFeaturizer(h_rf.return_comparator(), encoder, encryptor, scale)

def predict(args):
    """Performs HRF prediction"""
    # We first encrypt and evaluate our model on it
    index, x = args  # Unpack the tuple
    ctx = homomorphic_featurizer.encrypt(x)
    outputs = tree_evaluator(ctx)
    
    # We then decrypt it and get the first 2 values which are the classes scores
    ptx = seal.Plaintext()
    decryptor.decrypt(outputs, ptx)
    
    homomorphic_pred = encoder.decode(ptx)[:2]
    homomorphic_pred = np.argmax(homomorphic_pred)
    
    return index, homomorphic_pred

def main():

    # Prepare data for parallel processing
    X_valid_normalized = np.load("setup\X_valid.npy")
    data_with_indices = list(enumerate(X_valid_normalized))

    with ProcessPoolExecutor(max_workers=12) as executor:
        hrf_pred = list(tqdm(executor.map(predict, data_with_indices), total=len(data_with_indices)))

    # Because the outputs are unordered we must first sort by index then take the predictions
    hrf_pred = np.array(sorted(hrf_pred, key = lambda x:x[0]))[:,1]

    np.save("hrf_pred", hrf_pred)

if __name__ == '__main__':
    main()