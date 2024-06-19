
import sys
# adding Folder_2 to the system path
sys.path.insert(0, 'cryptotree')
from cryptoTree import HomomorphicNeuralRandomForest, HomomorphicTreeEvaluator
from polynomials import polyeval_tree
from seal_helper import load_seal_globals
from tree import SigmoidTreeMaker

from concurrent.futures import ProcessPoolExecutor
from tqdm import tqdm
import pickle
import seal
from pathlib import Path
import numpy as np
import socket
import os
import sys
from flask import Flask, request, jsonify
from flask_socketio import SocketIO, emit
from config import scale,dilatation_factor,polynomial_degree


app = Flask(__name__)
socketio = SocketIO(app)

# Load global variables
path = Path("seal_for_server")

parms = seal.EncryptionParameters(seal.scheme_type.ckks)
parms.load(str(path/"parms"))
context = seal.SEALContext(parms, True, seal.sec_level_type.tc128)

galois_keys = seal.GaloisKeys()
galois_keys.load(context, str(path/"galois_keys"))

relin_keys = seal.RelinKeys()
relin_keys.load(context, str(path/"relin_keys"))

encoder = seal.CKKSEncoder(context)

sigmoid_tree_maker = SigmoidTreeMaker(use_polynomial=True,
                                      dilatation_factor=dilatation_factor, polynomial_degree=polynomial_degree)

evaluator = seal.Evaluator(context)

model = pickle.load(open("setup\model.pkl" , "rb"))
h_rf = HomomorphicNeuralRandomForest(model)

tree_evaluator = HomomorphicTreeEvaluator.from_model(h_rf, sigmoid_tree_maker.coeffs,
                                                     polyeval_tree, evaluator, encoder, relin_keys, galois_keys,
                                                     scale)

@app.route('/predict', methods=['POST'])
def predict():
    if 'file' not in request.files:
        return jsonify({"error": "No file part"}), 400

    file = request.files['file']
    output_dir = request.form.get('output_dir')

    if file.filename == '':
        return jsonify({"error": "No selected file"}), 400

    if not output_dir:
        return jsonify({"error": "No output directory specified"}), 400

    input_path = Path("input")
    output_path = Path(output_dir)

    input_path.mkdir(parents=True, exist_ok=True)
    output_path.mkdir(parents=True, exist_ok=True)

    file_path = os.path.join(input_path, file.filename)
    file.save(file_path)

    data = np.load(file_path)
    data_enc = np.array([])

    for i in tqdm(data):
        ctx = context.from_cipher_str(i)
        data_enc = np.append(data_enc, ctx)

    outputs = np.array([])
    for idx, data in enumerate(tqdm(data_enc)):
        output = tree_evaluator(data)
        outputs = np.append(outputs, output.to_string())
        socketio.emit('progress', {'progress': int((idx + 1) / len(data_enc) * 100)})

    output_file_path = os.path.join(output_path, file.filename)
    np.save(output_file_path, outputs)

    return jsonify({"message": f"Computation done, file saved at {output_file_path}", "output_file": output_file_path}), 200

if __name__ == '__main__':
    socketio.run(app, debug=True, host='0.0.0.0')


