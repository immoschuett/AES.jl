module modAES
include("aes-modes.jl")
export AESEncrypt, AESDecrypt, AESParameters
export AESECB, AESCBC, AESCFB, AESOFB, AESCTR
end


# we use a 4 round toy cipher (4 round AES) ! 
m = UInt8.(b"0123456789abcdef")
const oraclekey = UInt8.(b"key2key1key1key1")
unzip(a) = map(x -> getfield.(a, x), fieldnames(eltype(a)))

# toy encryption with argument true
modAES.AESEncrypt(m, UInt8.(b"key0"), true)

# Enc_Oracle for CMA 
function Enc_oracle(m::Array{UInt8,1})
    # return c = ENC_AES_4(m) after 4 rounds. 
    return modAES.AESEncrypt(m, oraclekey, true)
end

#recover i-th byte of 4th roundkey by 
function recover_byte(i=1, Total_message_cnt=0)
    # ! NOTE: corresponding byte after 3 times shift rows (by our implementation)
    # 1  5  9  13 		# 1  5  9  13     		# a1 a5 a9  a13
    # 2  6  10 14		# 14 2  6  10			# a2 a6 a10 a14
    # 3  7  11 15   -> 	# 11 15 3  7	 where  # a3 a7 a11 a15
    # 4  8  12 16		# 8  12 16 4			# a4 a8 a12 a16
    # we can use readperm to gain access.
    readperm = [1, 6, 11, 16, 5, 10, 15, 4, 9, 14, 3, 8, 13, 2, 7, 12]
    Key_Candidates = []
    key = rand(UInt8, 16)
    for k::UInt8 = 0:255
        key[i] = k
        push!(Key_Candidates, copy(key))
    end
    while length(Key_Candidates) > 1
        Found_Candidates = []
        m = rand(UInt8, 16)
        # generate delta set for 1 byte, use encryption oracle to gain message/ciphertext pairs of fixed type
        C = []
        for k::UInt8 = 0:255
            m[i] = k
            push!(C, Enc_oracle(copy(m)))
            Total_message_cnt += 1
        end
        # for each key decrypt all ciphers and check for ... criterion 
        for key in Key_Candidates
            # decript
            D = []
            for c in C
                push!(D, modAES.AESLastRndInv(c, key))
            end
            # check if ⊻-sum is zero (at i-th byte)'
            d = UInt8(0)
            for entry in D
                d ⊻= entry[readperm[i]]
            end
            if d == 0
                push!(Found_Candidates, key)
            end
        end
        Key_Candidates = Found_Candidates
    end
    if Key_Candidates == []
        return []
    end
    #return Key_Candidates
    return Key_Candidates[1][i], Total_message_cnt
end
function recover_roundkey()
    Keydata = unzip([recover_byte(i) for i = 1:16])
    println("Number of C/M Pairs used: ", sum(Keydata[2]), "   #repetitions: ", Int(sum(Keydata[2]) / 256 - 16))
    return Keydata[1]
end
lastroundkey = modAES.KeyExpansion(oraclekey, 4, 4)[end-15:end]
byte = 1
recover_byte(byte)
recover_byte(byte)[1] == lastroundkey[byte]
recover_roundkey() == lastroundkey


using Test
@testset "modAES" begin
    @test modAES.AESDecrypt(modAES.AESEncrypt(m, oraclekey, true), oraclekey, true) == m
    @test recover_roundkey() == lastroundkey
end
