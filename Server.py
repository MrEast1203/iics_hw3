from flask import Flask, jsonify, request, Response, render_template
from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.hazmat.primitives import hashes
from cryptography.exceptions import InvalidSignature

app = Flask(__name__)


Users = [
	{
		"name": "example",
		"id": 1234,
		"publicKey": 1234
	}
]


@app.route("/")
def index():
    return render_template("index.html")

@app.route('/UserDB/<string:name>', methods=['GET', 'POST'])
def User(name):
	if request.method == 'GET':
		user = next(filter(lambda x: x['name'] == name, Users), None)
		if user:
			res = jsonify({'User': user})
			return res, 200
		else:
			res = jsonify({'message': 'User not found'})
			return res, 404
	elif request.method == 'POST':
		if next(filter(lambda x: x['name'] == name, Users), None):
			return jsonify({'message': f'An user with name {name} already exists ..'}), 403
		data = request.get_json()
		User = {'name': name, 'id': data['id'], 'publicKey': data['publicKey']}
		Users.append(User)
		res = jsonify(User)
		print(Users)
		return res, 201

@app.route('/UserDB/', methods=['GET'])

def UsersList():
	res = jsonify({'Users': Users})

	print(res)
	return res

@app.route('/Auth/<string:name>', methods=['POST'])
def AuthUser(name):
	user = next(filter(lambda x: x['name'] == name, Users), None)
	print(user)
	publickey = user['publicKey']
	curve = ec.SECP256R1()


	data = request.get_json()
	print(data)
	clientData = uint8array_from_dict(data['clientData'])
	authData = uint8array_from_dict(data['authData'])
	signature = uint8array_from_dict(data['signature'])
	print(publickey['-2'][str(0)])
	print(type(publickey['-2'][str(0)]))
	x=''
	for i in range(32):
		x=x+str(publickey['-2'][str(i)])
	y=''
	for i in range(32):
		y=y+str(publickey['-3'][str(i)])
	# TODO:驗證簽章的真偽（30分）
	publicKey=ec.EllipticCurvePublicNumbers(int(x), int(y), curve)
    # Hash the clientData and the authenticatorData
	clientData_hash = hashes.Hash(hashes.SHA256())
	clientData_hash.update(clientData)
	clientData_hash_digest = clientData_hash.finalize()
 

    # Concatenate the two hashes
	concatenated_hash = clientData_hash_digest + authData

    # Verify the signature using the public key
	try:
		publicKey.verify(signature, concatenated_hash, curve)
		print("Authentication successful")
		return "true", 201
	except:
		print("Authentication failed")
		return "false", 201



	

	


def uint8array_from_dict(str_dict):
	byte_array = bytearray(len(str_dict))
	for key, value in str_dict.items():
		byte_array[int(key)] = int(value)
	return bytes(byte_array)




if __name__ == "__main__":
	app.run(host='0.0.0.0',port=80, debug=True)
