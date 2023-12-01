module modAES
	include("aes-modes.jl")
	export AESEncrypt, AESDecrypt, AESParameters
	export AESECB, AESCBC, AESCFB, AESOFB, AESCTR
end


# 4 round toy cipher ! 
m = UInt8.(b"0123456789abcdef")
const oraclekey = UInt8.(b"key2key1key1key1")
#modAES.AESDecrypt(modAES.AESEncrypt(m,key,true),key,true) == m
#modAES.AESEncrypt(m,key,true) != modAES.AESEncrypt(m,key,false)

#modAES.AESEncrypt(m,UInt8.(b"key0"),true)

# 4th- round key 

# Enc_Oracle for CMA 
function Enc_oracle(m::Array{UInt8, 1})
	# return c = ENC_AES_4(m) after 4 rounds. 
	return modAES.AESEncrypt(m,oraclekey,true)
end 

#revover full 4-th roundkey 
# TODO

#recover i-th byte of 4th roundkey by 
function recover_byte(i=1)
	Key_Candidates = []
	key = rand(UInt8,16)
	for k::UInt8 = 0:255
		key[i] = k
		push!(Key_Candidates,copy(key))
	end 
	while length(Key_Candidates) > 1
		Found_Candidates = []
		m = rand(UInt8,16)
		# generate delta set for 1 byte, use encryption oracle to gain message/ciphertext pairs of fixed type
		C = []
		for k::UInt8 = 0:255
			m[i] = k
			println(m)
			push!(C,Enc_oracle(copy(m)))
		end 
		# for each key decrypt all ciphers and check for ... criterion 
		for key in Key_Candidates
			# decript
			D = []
			for c in C
				push!(D,modAES.AESLastRndInv(c, key))
			end 
			# check if ⊻-sum is zero (at i-th byte)
			d = UInt8(0)
			for entry in D
				d ⊻= entry[i]
			end
			if d == 0
				push!(Found_Candidates,key)
			end 
		end 
		Key_Candidates = Found_Candidates
	end 
	if Key_Candidates == []
		return []
	end 
	#return Key_Candidates
	return Key_Candidates[1][i]
end 

recover_byte(1)
# ! still BUG only found byte 1,5,9,13 correct  (this is only the first column of the inputdata) 
# TODO check for wrong MixColumns !
# ? or what else...
# fist byte of rnkey is 0xa7
oraclekey2 = UInt8.(b"aby1key1key1key2")
modAES.AESLastRndInv(m, oraclekey2)


# if 2 options -> new message (other)
oraclekey2 = UInt8.(b"aby1key1key1key2")

lastroundkey = modAES.KeyExpansion(oraclekey,4,4)[end-15:end]
