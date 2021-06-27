from Crypto.Cipher import AES
import struct,os,sys,random
import qrcode

nk31=0x59FC817E6446EA6190347B20E9BDCE52
pad=b"\x00"*4
hpad=b"\x55"*0x70

#decrypted mii qr code template	https://www.3dbrew.org/wiki/Mii
dec= b"\x03\x00\x00\x00" + b"\x00\x00\x00\x00" + b"\x00\x00\x00\x00" + b"\x08\x88\x88\x88"  #00 00 00 00 
dec+=b"\x77\x77\x77\x77" + b"\x77\x77\x00\x00" + b"\x00\x00\x00\x00" + b"\x00\x00\x00\x00"  #00 00 00 10
dec+=b"\x00\x00\x00\x00" + b"\x00\x00\x00\x00" + b"\x00\x00\x00\x00" + b"\x00\x00\x00\x00"  #00 00 00 20
dec+=b"\x00\x00\x00\x00" + b"\x00\x00\x00\x00" + b"\x00\x00\x00\x00" + b"\x00\x00\x00\x00"  #00 00 00 30
dec+=b"\x00\x00\x00\x00" + b"\x00\x00\x00\x00" + b"\x00\x00\x00\x00" + b"\x00\x00\x00\x00"  #00 00 00 40
dec+=b"\x00\x00\x00\x00" + b"\x00\x00\x00\x00" + b"\x00\x00\x00\x00" + b"\x44\x00\x44\x44"  #00 00 00 50

def changebits(offset, datasize, bitnum, bitsize, valuelimit, fixed):
	global dec
	bitmask=((2**bitsize)-1) << bitnum
	bitmask=(~bitmask) 
	value=0
	m1n=0

	if offset==0x38 and bitnum==25: # special minimum for this specific mii attribute (eyebrow y)
		m1n=3
	
	val=random.randint(m1n,valuelimit)
	newval=val << bitnum
	if fixed:
		newval=valuelimit << bitnum
		#print("Writing offset %04X   #%d / %d" % (offset,val,valuelimit))
	buff=dec[offset:offset+datasize]
	if datasize==1:
		type="<B"
	elif datasize==2:
		type="<H"
	elif datasize==4:
		type="<I"
	else:
		print("datasize must be 1, 2, or 4")
		sys.exit(1)
	value=struct.unpack(type,buff)[0]
	value&=bitmask
	value+=newval
	buff=struct.pack(type,value)
	dec = dec[:offset] + buff + dec[offset+datasize:]
	
def changename(offset, s, fixed):
    global dec
    if fixed:
        s=s.encode("utf-16le")
        s=s+(b"\00"*(0x14-len(s)))
    else:
        s=b""
        for i in range(6):
            s+=struct.pack("<H",random.randint(0x61,0x7A))
        for i in range(4):
            s+=struct.pack("<H",random.randint(0x30,0x39))
    dec = dec[:offset] + s[:0x14] + dec[offset+0x14:]
    
def int16bytes(n):
	s=b""
	for i in range(16):
		s=struct.pack("B", n&0xFF)+s
		n=n>>8
	return s

def encrypt(message, key, nonce):
	cipher = AES.new(key, AES.MODE_CCM, nonce)
	ciphertext, mac = cipher.encrypt_and_digest(message)
	return ciphertext, mac
	
def crc16(data):
	# Returns the hex digits of the CRC16 CCITT (XModem) value.
	# Thanks to https://stackoverflow.com/a/30357446
	crc = 0
	msb = crc >> 8
	lsb = crc & 0xFF
	for c in data:
		x = int(c) ^ msb
		x ^= (x >> 4)
		msb = (lsb ^ (x >> 3) ^ (x << 4)) & 0xFF
		lsb = (x ^ (x << 5)) & 0xFF
	crc = (msb << 8) + lsb
	return crc

def qrmake(num, isgold):
    global dec,nk31,pad,hpad
    sharing=0
    special=1
    qrcolor="white"
    if isgold:
        sharing=1
        special=0
        qrcolor="gold"
    #------------------------------------------------------------'''
    
    #names
    changename(0x1A, "Fishfishes", False)
    changename(0x48, "Company123", False)

    #copy
    changebits(0x1, 1, 0, 1, 0x1, True)
    
    #profanity
    changebits(0x1, 1, 1, 1, 0x0, True) #hides name with "???"
    
    #region lock
    changebits(0x1, 1, 2, 2, 0x0, True) #only affects special miis
    
    #char set
    changebits(0x1, 1, 4, 2, 0x0, True) #no effect?
    
    #mii system created on
    changebits(0x3, 1, 0, 4, 15, False)   #???
    changebits(0x3, 1, 4, 3, 3, True)   #system

    #system id
    changebits(0x4, 4, 0, 32, 0xFFFFFFFF, False)
    changebits(0x8, 4, 0, 32, 0xFFFFFFFF, False)
    
    
    #timestamp
    changebits(0xC+3, 1, 0, 8, 0xFF, False)
    changebits(0xC+2, 1, 0, 8, 0xFF, False)
    changebits(0xC+1, 1, 0, 8, 0xFF, False)
    changebits(0xC+0, 1, 0, 4, 0xF, False)
    
    #unknown
    changebits(0xC, 1, 4, 1, 0x1, True) #seems to need to be set
    
    #temporary mii
    changebits(0xC, 1, 5, 1, 0x0, True) #needs to be 0
    
    #DSi mii
    changebits(0xC, 1, 6, 0, 0x0, True)
    
    #unset means special
    changebits(0xC, 1, 7, 1, special, True) #golden param 1
    
    #mii id/nonce/mac
    changebits(0x10, 4, 0, 32, 0xFFFFFFFF, False)
    changebits(0x14, 2, 0, 16, 0xFFFF, False)

    #male/female
    changebits(0x18, 2, 0, 1, 1, False)
    
    #birthday month
    changebits(0x18, 2, 1, 4, random.randint(1,12), True)
    
    #birthday day
    changebits(0x18, 2, 5, 5, random.randint(1,28), True)

    #shirt color 
    changebits(0x18, 2, 10, 4, 11, False)
    
    #favorite
    changebits(0x18, 2, 14, 1, 1, False)

    #width
    changebits(0x2E, 1, 0, 7, 127, False)

    #height
    changebits(0x2F, 1, 0, 7, 127, False)

    #------------------------------------------------------------'''
    
    #sharing
    changebits(0x30, 1, 0, 1, sharing, True) #golden param 2
    
    #------------------------------------------------------------'''

    #face shape
    changebits(0x30, 1, 1, 4, 11, False)

    #face color
    changebits(0x30, 1, 5, 3, 5, False)

    #face wrinkles
    changebits(0x31, 1, 0, 4, 11, False)

    #face makeup
    changebits(0x31, 1, 4, 4, 11, False)

    #------------------------------------------------------------'''

    #hair style
    changebits(0x32, 1, 0, 8, 131, False)

    #hair color
    changebits(0x33, 1, 0, 3, 7, False)

    #hair flip
    changebits(0x33, 1, 3, 1, 1, False)

    #------------------------------------------------------------'''

    #eye style
    changebits(0x34, 4, 0, 6, 59, False)

    #eye color
    changebits(0x34, 4, 6, 3, 5, False)

    #eye scale
    changebits(0x34, 4, 9, 4, 7, False)

    #eye yscale
    changebits(0x34, 4, 13, 3, 6, False)

    #eye rotation
    changebits(0x34, 4, 16, 5, 7, False)

    #eye x spacing
    changebits(0x34, 4, 21, 4, 12, False)

    #eye y position
    changebits(0x34, 4, 25, 5, 18, False)

    #------------------------------------------------------------'''

    #eyebrow style
    changebits(0x38, 4, 0, 5, 23, False)

    #eyebrow color
    changebits(0x38, 4, 5, 3, 7, False)

    #eyebrow scale
    changebits(0x38, 4, 8, 4, 8, False)

    #eyebrow yscale
    changebits(0x38, 4, 12, 3, 6, False)

    #eyebrow rotation
    changebits(0x38, 4, 16, 4, 11, False)

    #eyebrow x spacing
    changebits(0x38, 4, 21, 4, 12, False)

    #eyebrow y position
    changebits(0x38, 4, 25, 5, 18, False)

    #------------------------------------------------------------'''

    #nose style
    changebits(0x3C, 2, 0, 5, 17, False)

    #nose scale
    changebits(0x3C, 2, 5, 4, 8, False)

    #nose y position
    changebits(0x3C, 2, 9, 5, 18, False)

    #------------------------------------------------------------'''

    #mouth style
    changebits(0x3E, 2, 0, 6, 35, False)

    #mouth color
    changebits(0x3E, 2, 6, 3, 4, False)

    #mouth scale
    changebits(0x3E, 2, 9, 4, 8, False)

    #mouth yscale
    changebits(0x3E, 2, 13, 3, 6, False)

    #------------------------------------------------------------'''

    #mouth y position
    changebits(0x40, 2, 0, 5, 18, False)

    #mustache style
    changebits(0x40, 2, 5, 3, 5, False)

    #------------------------------------------------------------'''

    #beard style
    changebits(0x42, 2, 0, 3, 5, False)

    #beard color
    changebits(0x42, 2, 3, 3, 7, False)

    #mustache scale
    changebits(0x42, 2, 6, 4, 8, False)

    #mustache y position
    changebits(0x42, 2, 10, 5, 16, False)


    #------------------------------------------------------------'''

    #glasses style
    changebits(0x44, 2, 0, 4, 8, False)

    #glasses color
    changebits(0x44, 2, 4, 3, 5, False)

    #glasses scale
    changebits(0x44, 2, 7, 4, 7, False)

    #glasses yposition
    changebits(0x44, 2, 11, 5, 20, False)


    #------------------------------------------------------------'''


    #mole enable
    changebits(0x46, 2, 0, 1, 1, False)

    #mole scale
    changebits(0x46, 2, 1, 4, 8, False)

    #mole x position
    changebits(0x46, 2, 5, 5, 16, False)

    #mole y position
    changebits(0x46, 2, 10, 5, 30, False)


    #------------------------------------------------------------'''

    print("QR %d" % num)

    dec=dec[:0x5E]+struct.pack(">H",crc16(dec[:0x5E]))

    nonce=dec[12:12+8]+pad
    enc,mac=encrypt(dec[:12]+dec[20:0x60]+(pad*2), int16bytes(nk31), nonce)
    final=nonce[:8]+enc[:0x58]+mac

    qr = qrcode.QRCode(
        version=10,
        error_correction=qrcode.constants.ERROR_CORRECT_H,
        box_size=4,
        border=4,
    )
    qr.add_data(final+(hpad*0))
    qr.make(fit=True)
    img = qr.make_image(fill_color="black", back_color=qrcolor)
    img.save("qr/qr%d.png" % num)
    
    with open("res/res%d.bin" % num,"wb") as f:
        f.write(dec)

isgold = False
if len(sys.argv) == 2:
    isgold = sys.argv[1].lower() == "gold"
if isgold:
    print("Gold Pants Miis selected!")
else:
    print("Regular Pants Miis selected!")

for i in range(20):
    qrmake(i, isgold)
os.system("index.html")
print("Done")