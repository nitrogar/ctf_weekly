from z3 import *
def print_ddt(ddt, max_rows=30, max_cols=30):
      """Print the DDT in a formatted way, limited to specified dimensions."""
      print("\nDifferential Distribution Table (partial):")
      print("   |", end=" ")

      # Print header
      for j in range(max_cols):
          print(f"{j:2X}", end=" ")
      print("\n---+" + "---" * max_cols)

      # Print rows
      for i in range(max_rows):
          print(f"{i:2X} |", end=" ")
          for j in range(max_cols):
              print(f"{ddt[i][j]}", end=" ")
          print()


def print_state(state_list):
  # Get the maximum length of string representation
  max_len = max(len(str(x)) for x in state_list)
  padding = max_len + 2  # Add 2 for some extra space

  # Calculate total width for the box
  total_width = (padding * 4) + 3  # 4 columns, +3 for spaces between

  # Print with box drawing and adaptive width
  print('┌' + '─' * total_width + '┐')
  for i in range(4):
      row = ' '.join(f'{str(state_list[i*4 + j]):{padding}}' for j in range(4))
      print(f'│ {row} │')
  print('└' + '─' * total_width + '┘')
def mult2(x):
  return If(Extract(7,7,x) == 1, (x << 1) ^ BitVecVal(0x1b, 8), x << 1)
def mult9(x):  # 9 = 8 + 1 = ((2²)²) + 1
  double = If(Extract(7,7,x) == 1, (x << 1) ^ 0x1b, x << 1)
  double2 = If(Extract(7,7,double) == 1, (double << 1) ^ 0x1b, double << 1)
  double4 = If(Extract(7,7,double2) == 1, (double2 << 1) ^ 0x1b, double2 << 1)
  return double4 ^ x  # 8x + x

def mult11(x):  # 11 = 8 + 2 + 1 = ((2²)²) + 2 + 1
  double = If(Extract(7,7,x) == 1, (x << 1) ^ 0x1b, x << 1)
  double2 = If(Extract(7,7,double) == 1, (double << 1) ^ 0x1b, double << 1)
  double4 = If(Extract(7,7,double2) == 1, (double2 << 1) ^ 0x1b, double2 << 1)
  return double4 ^ double ^ x  # 8x + 2x + x

def mult13(x):  # 13 = 8 + 4 + 1 = ((2²)²) + (2²) + 1
  double = If(Extract(7,7,x) == 1, (x << 1) ^ 0x1b, x << 1)
  double2 = If(Extract(7,7,double) == 1, (double << 1) ^ 0x1b, double << 1)
  double4 = If(Extract(7,7,double2) == 1, (double2 << 1) ^ 0x1b, double2 << 1)
  return double4 ^ double2 ^ x  # 8x + 4x + x

def mult14(x):  # 14 = 8 + 4 + 2 = ((2²)²) + (2²) + 2
  double = If(Extract(7,7,x) == 1, (x << 1) ^ 0x1b, x << 1)
  double2 = If(Extract(7,7,double) == 1, (double << 1) ^ 0x1b, double << 1)
  double4 = If(Extract(7,7,double2) == 1, (double2 << 1) ^ 0x1b, double2 << 1)
  return double4 ^ double2 ^ double  # 8x + 4x + 2x

s_box = (
    0x63, 0x7C, 0x77, 0x7B, 0xF2, 0x6B, 0x6F, 0xC5, 0x30, 0x01, 0x67, 0x2B, 0xFE, 0xD7, 0xAB, 0x76,
    0xCA, 0x82, 0xC9, 0x7D, 0xFA, 0x59, 0x47, 0xF0, 0xAD, 0xD4, 0xA2, 0xAF, 0x9C, 0xA4, 0x72, 0xC0,
    0xB7, 0xFD, 0x93, 0x26, 0x36, 0x3F, 0xF7, 0xCC, 0x34, 0xA5, 0xE5, 0xF1, 0x71, 0xD8, 0x31, 0x15,
    0x04, 0xC7, 0x23, 0xC3, 0x18, 0x96, 0x05, 0x9A, 0x07, 0x12, 0x80, 0xE2, 0xEB, 0x27, 0xB2, 0x75,
    0x09, 0x83, 0x2C, 0x1A, 0x1B, 0x6E, 0x5A, 0xA0, 0x52, 0x3B, 0xD6, 0xB3, 0x29, 0xE3, 0x2F, 0x84,
    0x53, 0xD1, 0x00, 0xED, 0x20, 0xFC, 0xB1, 0x5B, 0x6A, 0xCB, 0xBE, 0x39, 0x4A, 0x4C, 0x58, 0xCF,
    0xD0, 0xEF, 0xAA, 0xFB, 0x43, 0x4D, 0x33, 0x85, 0x45, 0xF9, 0x02, 0x7F, 0x50, 0x3C, 0x9F, 0xA8,
    0x51, 0xA3, 0x40, 0x8F, 0x92, 0x9D, 0x38, 0xF5, 0xBC, 0xB6, 0xDA, 0x21, 0x10, 0xFF, 0xF3, 0xD2,
    0xCD, 0x0C, 0x13, 0xEC, 0x5F, 0x97, 0x44, 0x17, 0xC4, 0xA7, 0x7E, 0x3D, 0x64, 0x5D, 0x19, 0x73,
    0x60, 0x81, 0x4F, 0xDC, 0x22, 0x2A, 0x90, 0x88, 0x46, 0xEE, 0xB8, 0x14, 0xDE, 0x5E, 0x0B, 0xDB,
    0xE0, 0x32, 0x3A, 0x0A, 0x49, 0x06, 0x24, 0x5C, 0xC2, 0xD3, 0xAC, 0x62, 0x91, 0x95, 0xE4, 0x79,
    0xE7, 0xC8, 0x37, 0x6D, 0x8D, 0xD5, 0x4E, 0xA9, 0x6C, 0x56, 0xF4, 0xEA, 0x65, 0x7A, 0xAE, 0x08,
    0xBA, 0x78, 0x25, 0x2E, 0x1C, 0xA6, 0xB4, 0xC6, 0xE8, 0xDD, 0x74, 0x1F, 0x4B, 0xBD, 0x8B, 0x8A,
    0x70, 0x3E, 0xB5, 0x66, 0x48, 0x03, 0xF6, 0x0E, 0x61, 0x35, 0x57, 0xB9, 0x86, 0xC1, 0x1D, 0x9E,
    0xE1, 0xF8, 0x98, 0x11, 0x69, 0xD9, 0x8E, 0x94, 0x9B, 0x1E, 0x87, 0xE9, 0xCE, 0x55, 0x28, 0xDF,
    0x8C, 0xA1, 0x89, 0x0D, 0xBF, 0xE6, 0x42, 0x68, 0x41, 0x99, 0x2D, 0x0F, 0xB0, 0x54, 0xBB, 0x16,
)

inv_s_box = (
    0x52, 0x09, 0x6A, 0xD5, 0x30, 0x36, 0xA5, 0x38, 0xBF, 0x40, 0xA3, 0x9E, 0x81, 0xF3, 0xD7, 0xFB,
    0x7C, 0xE3, 0x39, 0x82, 0x9B, 0x2F, 0xFF, 0x87, 0x34, 0x8E, 0x43, 0x44, 0xC4, 0xDE, 0xE9, 0xCB,
    0x54, 0x7B, 0x94, 0x32, 0xA6, 0xC2, 0x23, 0x3D, 0xEE, 0x4C, 0x95, 0x0B, 0x42, 0xFA, 0xC3, 0x4E,
    0x08, 0x2E, 0xA1, 0x66, 0x28, 0xD9, 0x24, 0xB2, 0x76, 0x5B, 0xA2, 0x49, 0x6D, 0x8B, 0xD1, 0x25,
    0x72, 0xF8, 0xF6, 0x64, 0x86, 0x68, 0x98, 0x16, 0xD4, 0xA4, 0x5C, 0xCC, 0x5D, 0x65, 0xB6, 0x92,
    0x6C, 0x70, 0x48, 0x50, 0xFD, 0xED, 0xB9, 0xDA, 0x5E, 0x15, 0x46, 0x57, 0xA7, 0x8D, 0x9D, 0x84,
    0x90, 0xD8, 0xAB, 0x00, 0x8C, 0xBC, 0xD3, 0x0A, 0xF7, 0xE4, 0x58, 0x05, 0xB8, 0xB3, 0x45, 0x06,
    0xD0, 0x2C, 0x1E, 0x8F, 0xCA, 0x3F, 0x0F, 0x02, 0xC1, 0xAF, 0xBD, 0x03, 0x01, 0x13, 0x8A, 0x6B,
    0x3A, 0x91, 0x11, 0x41, 0x4F, 0x67, 0xDC, 0xEA, 0x97, 0xF2, 0xCF, 0xCE, 0xF0, 0xB4, 0xE6, 0x73,
    0x96, 0xAC, 0x74, 0x22, 0xE7, 0xAD, 0x35, 0x85, 0xE2, 0xF9, 0x37, 0xE8, 0x1C, 0x75, 0xDF, 0x6E,
    0x47, 0xF1, 0x1A, 0x71, 0x1D, 0x29, 0xC5, 0x89, 0x6F, 0xB7, 0x62, 0x0E, 0xAA, 0x18, 0xBE, 0x1B,
    0xFC, 0x56, 0x3E, 0x4B, 0xC6, 0xD2, 0x79, 0x20, 0x9A, 0xDB, 0xC0, 0xFE, 0x78, 0xCD, 0x5A, 0xF4,
    0x1F, 0xDD, 0xA8, 0x33, 0x88, 0x07, 0xC7, 0x31, 0xB1, 0x12, 0x10, 0x59, 0x27, 0x80, 0xEC, 0x5F,
    0x60, 0x51, 0x7F, 0xA9, 0x19, 0xB5, 0x4A, 0x0D, 0x2D, 0xE5, 0x7A, 0x9F, 0x93, 0xC9, 0x9C, 0xEF,
    0xA0, 0xE0, 0x3B, 0x4D, 0xAE, 0x2A, 0xF5, 0xB0, 0xC8, 0xEB, 0xBB, 0x3C, 0x83, 0x53, 0x99, 0x61,
    0x17, 0x2B, 0x04, 0x7E, 0xBA, 0x77, 0xD6, 0x26, 0xE1, 0x69, 0x14, 0x63, 0x55, 0x21, 0x0C, 0x7D,
)

def sub_bytes(s):
    for i in range(4):
        for j in range(4):
            s[i][j] = s_box[s[i][j]]


def inv_sub_bytes(s):
    for i in range(4):
        for j in range(4):
            s[i][j] = inv_s_box[s[i][j]]


def shift_rows(s):
    s[0][1], s[1][1], s[2][1], s[3][1] = s[1][1], s[2][1], s[3][1], s[0][1]
    s[0][2], s[1][2], s[2][2], s[3][2] = s[2][2], s[3][2], s[0][2], s[1][2]
    s[0][3], s[1][3], s[2][3], s[3][3] = s[3][3], s[0][3], s[1][3], s[2][3]


def inv_shift_rows(s):
    s[0][1], s[1][1], s[2][1], s[3][1] = s[3][1], s[0][1], s[1][1], s[2][1]
    s[0][2], s[1][2], s[2][2], s[3][2] = s[2][2], s[3][2], s[0][2], s[1][2]
    s[0][3], s[1][3], s[2][3], s[3][3] = s[1][3], s[2][3], s[3][3], s[0][3]

def add_round_key(s, k):
    
    for i in range(4):
        for j in range(4):
            s[i][j] ^= k[i][j]


# learned from http://cs.ucsb.edu/~koc/cs178/projects/JT/aes.c
xtime = lambda a: (((a << 1) ^ 0x1B) & 0xFF) if (a & 0x80) else (a << 1)


def mix_single_column(a):
    # see Sec 4.1.2 in The Design of Rijndael
    t = a[0] ^ a[1] ^ a[2] ^ a[3]
    u = a[0]
    a[0] ^= t ^ xtime(a[0] ^ a[1])
    a[1] ^= t ^ xtime(a[1] ^ a[2])
    a[2] ^= t ^ xtime(a[2] ^ a[3])
    a[3] ^= t ^ xtime(a[3] ^ u)


def mix_single_column_map(a):
    # see Sec 4.1.2 in The Design of Rijndael
    t = a[0] ^ a[1] ^ a[2] ^ a[3]
    u = a[0]
    a[0] ^= t ^ xtime(a[0] ^ a[1])
    a[1] ^= t ^ xtime(a[1] ^ a[2])
    a[2] ^= t ^ xtime(a[2] ^ a[3])
    a[3] ^= t ^ xtime(a[3] ^ u)
    return a

def mix_columns(s):
    for i in range(4):
        mix_single_column(s[i])


def inv_mix_columns(s):
    # see Sec 4.1.3 in The Design of Rijndael
    for i in range(4):
        u = xtime(xtime(s[i][0] ^ s[i][2]))
        v = xtime(xtime(s[i][1] ^ s[i][3]))
        s[i][0] ^= u
        s[i][1] ^= v
        s[i][2] ^= u
        s[i][3] ^= v

    mix_columns(s)
def inv_mix_single_column_map(s: bytearray):
    # see Sec 4.1.3 in The Design of Rijndael
        u = xtime(xtime(s[0] ^ s[2]))
        v = xtime(xtime(s[1] ^ s[3]))
        s[0] ^= u
        s[1] ^= v
        s[2] ^= u
        s[3] ^= v

        return mix_single_column_map(s)


def bytes2matrix(text):
    """ Converts a 16-byte array into a 4x4 matrix.  """
    return [list(text[i:i+4]) for i in range(0, len(text), 4)]

def matrix2bytes(matrix):
    """ Converts a 4x4 matrix into a 16-byte array.  """
    return bytes(sum(matrix, []))


def init_tables():
      size = len(s_box)
      ddt = {}
      ddti = {}
      ddt_lookup = {}
      for delta_in in range(size):
            for x in range(size):
                  y1 = s_box[x]
                  y2 = s_box[x ^ delta_in]
                  delta_out = y1 ^ y2
                  in_key = hex(delta_in)
                  out_val = hex(delta_out)

                  if in_key not in ddt:
                        ddt[in_key] = []
                        ddt_lookup[in_key] = {}
                  if out_val not in ddt[in_key]:
                        ddt[in_key] += [out_val]
                        if out_val not in  ddt_lookup[in_key]:
                              ddt_lookup[in_key][out_val] = []
                  ddt_lookup[in_key][out_val] += [hex(y1)]


      for delta_in in range(size):
            for x in range(size):
                  y1 = inv_s_box[x]
                  y2 = inv_s_box[x ^ delta_in]
                  delta_out = y1 ^ y2
                  in_key = hex(delta_in)
                  out_val = hex(delta_out)
                  if in_key not in ddti:
                        ddti[in_key] = []
                  if out_val not in ddti[in_key]:
                        ddti[in_key] += [out_val]

      ddt_lookup['0x0']['0x0'] = [hex(0) , hex(0)]
      return ddt, ddti, ddt_lookup

# | plain    | 241d2cc711104f05beb283c82c7e0d8c | 271d2cc711104f05beb283c82c7e0d8c |  3000000000000000000000000000000 |   |
# | add keys | 655c6d8650510e44fff3c2896d3f4ccd | 665c6d8650510e44fff3c2896d3f4ccd |  3000000000000000000000000000000 |   |
# | shift    | 6551c2cd50f34c86ff3f6d446d5c0e89 | 6651c2cd50f34c86ff3f6d446d5c0e89 |  3000000000000000000000000000000 |   |
# | sbox     | 4dd125bd530d294416753c1b3c4aaba7 | 33d125bd530d294416753c1b3c4aaba7 | 7e000000000000000000000000000000 |   |
# | add keys | 8e13e77fd18eaac7d5b7fed9bec92824 | f013e77fd18eaac7d5b7fed9bec92824 | 7e000000000000000000000000000000 |   |
# | sbox     | 197d94d23e19acc603a9bb35aedd3436 | 8c7d94d23e19acc603a9bb35aedd3436 | 95000000000000000000000000000000 |   |



# | plain    | cf2a0359ded64cc28d5ff472218bee0c | cc2a0359ded64cc28d5ff472218bee0c |  3000000000000000000000000000000 |
# | add keys | 8e6b42189f970d83cc1eb53360caaf4d | 8d6b42189f970d83cc1eb53360caaf4d |  3000000000000000000000000000000 |
# | shift    | 8e97b54d9f1eaf18ccca4283606b0d33 | 8d97b54d9f1eaf18ccca4283606b0d33 |  3000000000000000000000000000000 |
# | sbox     | 1988d5e3db7279ad4b742cecd07fd7c3 | 5d88d5e3db7279ad4b742cecd07fd7c3 | 44000000000000000000000000000000 |
# | mix      | 87951eabef19b73cca3b48462e8f445e | 0fd15a67ef19b73cca3b48462e8f445e | 884444cc000000000000000000000000 |
# | add keys | 4457dc696d9a34bf09f98a84ac0cc7dd | cc1398a56d9a34bf09f98a84ac0cc7dd | 884444cc000000000000000000000000 |
# | sbox     | 1b5b86f93cb8180801997e5f91fec6c1 | 4b7d46063cb8180801997e5f91fec6c1 | 5026c0ff000000000000000000000000 |
# | shift    | 1bb87ec13c99c6f901fe8608915b185f | 4bb87ec13c99c60601fe4608917d185f | 50000000000000ff0000c00000260000 |
# | mix      | 5a330772f7bd22f2957ff06b93501b55 | fa6357820842381755246babf91c3d73 | a05050f0ffff1ae5c05b9bc06a4c2626 |
# | add keys | 771d29a358108fa0f9109ffb7dbcf746 | d74d7953a7ef9545394b043b17f0d160 | a05050f0ffff1ae5c05b9bc06a4c2626 |
# |          |                                  |                                  |                                0 |
# |
# | plain    | 948fbef8b20b4c4dbb532888ad3e4f32 | 0ffaeaf0eb6702fb15ed1e5111bdd95f |
# | add keys | d5ceffb9f34a0d0cfa1269c9ec7f0e73 | 4ebbabb1aa2643ba54ac5f1050fc981e |
# | shift    | d54a6973f3120eb9fa7fff0cecce0dc9 | 4e265f1eaaac98b154fcabba50bb4310 |
# | sbox     | 03d6f98f0dc9ab562dd216fece8bd7dd | 2ff7cf72ac9146c820b062f453ea1aca |
# | mix      | 112bb62fa73473d9df56ca540b7c8cb4 | e1e2cbad6597f2b31d0953415378c88a |
# | add keys | d2e974ed25b7f05a1c94089689ff0f37 | 2220096fe7147130decb9183d1fb4b09 |
# | sbox     | b51e92553fa98cbe9c223090a716769a | 93b701a894faa3041d1f81ec3e0fb301 |
# | shift    | b5a9309a3f2276559c1692bea71e8c90 | 93fa8101941fb3a81d0f01043eb7a3ec |
# | mix      | 3b36c9723bb40ebf35a36c5c6b84115b | a8e573d709cc15402e041c21f159fb95 |
# | add keys | 1618e7a39419a3ed59cc03cc8568fd48 | 85cb5d06a661b812426b73b11fb51786 |

# | plain    | 78bbd1ae6c4b44a5a158bf90f7d74a87 |8a33188c83f4434eae8da231fa4f22ea |
# | add keys | 39fa90ef2d0a05e4e019fed1b6960bc6 |cb7259cdc2b5020fefcce370bb0e63ab |
# | shift    | 390afec62d190befe09690e4b6fa05d1 |cbb5e3abc2cc63cdef0e590fbb720270 |
# | sbox     | 1267bbb4d8d42bdfe19060694e2d6b3e |1fd51162254bfbbddfabcb76ea407751 |
# | mix      | 82bedf9938c920297b130a1abe97f7e8 |29ff4e21d1185fbefea263f629a2b7b0 |
# | add keys | 417c1d5bba4aa3aab8d1c8d83c14746b |ea3d8ce3539bdc3d3d60a134ab213433 |
# | sbox     | 8310a439f4d60aac6c3ee861ebfa927f |87276411ed14862727d0321862fd18c3 |
# | shift    | 83d6e87ff43e92396cfaa4aceb100a61 |871432c3edd0181127fd642762278618 |
# | mix      | eb681f5e1a1cbed9c5d82aa996b44cfe |d83aa929a36f3ec6114d7bbe33a57a37 |
# | add keys | c646318fb5b1138ba9b745397858a0ed |f51487f80cc293947d22142edd499624 |
# |          |                                  |
# |

# | plain    | 78bbd1ae6c4b44a5a158bf90f7d74a87 | 8a33188c83f4434eae8da231fa4f22ea | f288c922efbf07eb0fd51da10d98686d |
# | add keys | 39fa90ef2d0a05e4e019fed1b6960bc6 | cb7259cdc2b5020fefcce370bb0e63ab | f288c922efbf07eb0fd51da10d98686d |
# | shift    | 390afec62d190befe09690e4b6fa05d1 | cbb5e3abc2cc63cdef0e590fbb720270 | f2bf1d6defd568220f98c9eb0d8807a1 |
# | sbox     | 1267bbb4d8d42bdfe19060694e2d6b3e | 1fd51162254bfbbddfabcb76ea407751 | db2aad6fd9fd0623e3bab1fa46d1c6f  |
# | mix      | 82bedf9938c920297b130a1abe97f7e8 | 29ff4e21d1185fbefea263f629a2b7b0 | ab4191b8e9d17f9785b169ec97354058 |
# | add keys | 417c1d5bba4aa3aab8d1c8d83c14746b | ea3d8ce3539bdc3d3d60a134ab213433 | ab4191b8e9d17f9785b169ec97354058 |
# | sbox     | 8310a439f4d60aac6c3ee861ebfa927f | 87276411ed14862727d0321862fd18c3 | 437c02819c28c8b4beeda7989078abc  |
# | shift    | 83d6e87ff43e92396cfaa4aceb100a61 | 871432c3edd0181127fd642762278618 | 4c2dabc19ee8a284b07c08b89378c79  |
# | mix      | eb681f5e1a1cbed9c5d82aa996b44cfe | d83aa929a36f3ec6114d7bbe33a57a37 | 3352b677b973801fd4955117a51136c9 |
# | add keys | c646318fb5b1138ba9b745397858a0ed | f51487f80cc293947d22142edd499624 | 3352b677b973801fd4955117a51136c9 |
# |          |                                  |                                  | 0                                |
# |          |                                  |                                  | 0                                |

from itertools import product
def ddt_map(x):
      return ddt[x]

p0 = bytearray.fromhex('78bbd1ae6c4b44a5a158bf90f7d74a87')
p1 = bytearray.fromhex('8a33188c83f4434eae8da231fa4f22ea')
c0 = bytearray.fromhex('c646318fb5b1138ba9b745397858a0ed')
c1 = bytearray.fromhex('f51487f80cc293947d22142edd499624')

ddt,ddti,ddt_lookup= init_tables()


delta_ins = [x^y for x,y in zip(p0,p1)]
delta_outs = [x^y for x,y in zip(c0,c1)]

delta_outs = bytes2matrix(delta_outs)
delta_ins  =  bytes2matrix(delta_ins)
shift_rows(delta_ins)

inv_mix_columns(delta_outs)
inv_shift_rows(delta_outs)

delta_outs = matrix2bytes(delta_outs)
delta_ins = matrix2bytes(delta_ins)
print("=============================================================")
print(f"P: {delta_ins.hex()}")
print("=============================================================")
print(f"C: {delta_outs.hex()}")
print("=============================================================")

after_first_sbox = [ddt[hex(x)] for x in delta_ins]
print("=============================================================")
print([len(x) for x in after_first_sbox])
# print(after_first_sbox[:4])
print("=============================================================")
for i in range(0,4):
      all_possible_sbox_outs = []
      for progress, x0 in enumerate(after_first_sbox[i]):
            print(f"{progress / len(after_first_sbox[0]) * 100:.2f}")
            for x1 in after_first_sbox[i+1]:
                  for x2 in after_first_sbox[i+2]:
                        for x3 in after_first_sbox[i+3]:
                              x = [x0,x1,x2,x3]
                              all_possible_sbox_outs.append(bytearray(map(lambda l: int(l, 16), x)))
      for dd in all_possible_sbox_outs:
            print(dd)
      break
      after_first_sbox = bytes2matrix(after_first_sbox)
      c0_list = [bytearray(map(lambda x: int(x,16), combo)) for combo in product(*after_first_sbox[i])]
      print("=============================================================")
      # print(c0_list)
      print("=============================================================")
      c0_list = list(map(mix_single_column_map, c0_list))
      print("=============================================================")
      for i,j in enumerate(c0_list):
            break
            print(f"{i} ==> {j.hex()}")
      print("=============================================================")

      before_second_sbox = [ddti[hex(x)] for x in delta_outs]
      print("=============================================================")
      print([len(x) for x in before_second_sbox])
      # print(before_second_sbox[:4])
      print("=============================================================")
      all_combos =  product(*before_second_sbox[:4])
      middle_candidate = []
      for i,combo in enumerate(all_combos):
            print(f"[%{i/127**4 * 100:.2f}] {i} / {127**4}", end='\r')
            c0 = bytearray(map(lambda x: int(x,16), combo))
            # print("=============================================================")
            # print(c0.hex())
            # print("=============================================================")
            # c0_mix = inv_mix_single_column_map(c0)
            # print("=============================================================")
            # print(c0_mix.hex())
            # print("=============================================================")
            if c0 in c0_list:
                  middle_candidate.append(c0)
                  print(f"[%{i/127**4 * 100:.2f}] {i} found {c0.hex()}")
            else:
                  pass

      # [%21.63] 56266848 found 884444cc
      # [%30.35] 78948216 found 2c16163a
      # [%36.37] 94602378 found 49a9a9e0
      # [%69.32] 180324138 found 53a4a4f7
      # [%86.08] 223931549 found 399191a8

      middle_candidate.append(bytearray.fromhex('884444cc'))
      middle_candidate.append(bytearray.fromhex('2c16163a'))
      middle_candidate.append(bytearray.fromhex('49a9a9e0'))
      middle_candidate.append(bytearray.fromhex('53a4a4f7'))
      middle_candidate.append(bytearray.fromhex('399191a8'))

      key_candidate = []
      for m in middle_candidate:
            state = inv_mix_single_column_map(m)
            print(f"possible intermediate state before mixcolumn: {state.hex()}")
            state = bytearray([int(ddt_lookup[hex(ins)][hex(outs)][1],16) for ins, outs in zip(delta_ins,state)])
            print(f"possible intermediate state after sbox: {state.hex()}")
            state = bytearray([inv_s_box[x] for x in state])
            print(f"possible intermediate state before sbox: {state.hex()}")
            #state = unshift by i
            print(f"possible intermediate state before shifting: {state.hex()}")
            plain_c0 = p0[:4]
            state = bytearray([x ^ y  for x,y in zip(plain_c0,state)])
            print(f"possible key candidates: {state.hex()}")
            key_candidate.append(state)
            # print(f"{i} NOT {c0_mix}")
# c0_list_b = list(map(mix_single_column_map, c0_list_b))
# c0_list_b = [bytearray(map(lambda x: int(x,16), combo)) for combo in product(*before_second_sbox[:4])]
# #flatten = [i for k in ddt for i in k]
# # # Try with just one byte first
# # solver = Solver()
# # s_sbox = Array('s_sbox', BitVecSort(8), BitVecSort(8))
# # s_isbox = Array('s_isbox', BitVecSort(8), BitVecSort(8))

# #
# Setup S-box for just a few values
# for i, s in enumerate(s_box):
#    s_sbox = Store(s_sbox, BitVecVal(i,8), BitVecVal(s, 8))
#     #solver.add(Select(s_sbox, BitVecVal(i,8)) == BitVecVal(s,8))
# for i, s in enumerate(inv_s_box):
#     s_isbox = Store(s_isbox, BitVecVal(i,8), BitVecVal(s, 8))
#     #solver.add(Select(s_isbox, BitVecVal(i,8)) == BitVecVal(s,8))

# # Try with single byte
# p0_byte = BitVec('p0_0', 8)
# p1_byte = BitVec('p1_0', 8)
# c0_byte = BitVec('c0_0', 8)
# c1_byte = BitVec('c1_0', 8)

# x0 = BitVec('x0_0', 8)
# x1 = BitVec('x1_0', 8)

# solver.add(p0_byte == p0[0])
# solver.add(p1_byte == p1[0])
# solver.add(c0_byte == c0[0])
# solver.add(c1_byte == c1[0])

# solver.add(x0 == Select(s_sbox, p0_byte) ^ Select(s_sbox, p1_byte))
# print("After x0 constraint:", solver.check())
# solver.add(x1 == Select(s_isbox, c0_byte) ^ Select(s_isbox,  c1_byte))
# print("After x1 constraint:", solver.check())

# solver.add(x1 == x0)
# print(f"x0 expected: 0x{x0}")
# print(f"x1 expected: 0x{x1}")

# if solver.check() == sat:
#     m = solver.model()
#     x0_val = m[x0].as_long()
#     x1_val = m[x1].as_long()
#     print(f"Found solution for x0 byte: 0x{x0_val:02x}")
#     print(f"Found solution for x1 byte: 0x{x1_val:02x}")


# print("Done")

















# # p0 = bytearray.fromhex('241d2cc711104f05beb283c82c7e0d8c')
# p1 = bytearray.fromhex('271d2cc711104f05beb283c82c7e0d8c')
# c0 = bytearray.fromhex('343795e7910499806fb2fb5640914026')
# c1 = bytearray.fromhex('a13795e7910499806fb2fb5640914026')

# solver = Solver()
# # define sbox

# s_sbox = Array('s_sbox', BitVecSort(8), BitVecSort(8))
# s_isbox = Array('s_isbox', BitVecSort(8), BitVecSort(8))
# s_index = BitVec('s_index',8)
# solver.add(s_index >= 0)
# solver.add(s_index <= 0xff)
# # polulate sbox
# for i, s in enumerate(s_box):
#     # s_sbox = Store(s_sbox, BitVecVal(i,8), BitVecVal(s, 8))
#     solver.add(Select(s_sbox,BitVecVal(i,8)) == BitVecVal(s,8))
# for i, s in enumerate(inv_s_box):
#     solver.add(Select(s_isbox,BitVecVal(i,8)) == BitVecVal(s,8))


# print("Done Initializing SBOX, ISBOX")
# p0_bytes =[BitVec(f'p0_{i}',8) for i in range(16)]
# p1_bytes =[BitVec(f'p1_{i}',8) for i in range(16)]
# c0_bytes =[BitVec(f'c0_{i}',8) for i in range(16)]
# c1_bytes =[BitVec(f'c1_{i}',8) for i in range(16)]
# # bytes to aes state
# p0_state = [p0_bytes[i+j*4] for i in range(4) for j in range(4)]
# p1_state = [p1_bytes[i+j*4] for i in range(4) for j in range(4)]
# c0_state = [c0_bytes[i+j*4] for i in range(4) for j in range(4)]
# c1_state = [c1_bytes[i+j*4] for i in range(4) for j in range(4)]

# intermediate_state_start = [BitVec(f'x0_{i}',8) for i in range(16)]
# intermediate_state_end = [BitVec(f'x1_{i}',8) for i in range(16)]

# for i in range(16):
#     solver.add(intermediate_state_start[i] == Select(s_sbox,p0_state[i]) ^ Select(s_sbox,p0_state[i] ^ p1_state[i]))

# output_state = [_ for _ in range(16)]


# for i in range(16):
#   solver.add(intermediate_state_end[i] == Select(s_isbox, c0_state[i]) ^ Select(s_isbox, c0_state[i] ^ c1_state[i]))

# for i in range(16):
#    solver.add(p0_bytes[i] == p0[i])
#    solver.add(p1_bytes[i] == p1[i])
#    solver.add(c0_bytes[i] == c0[i])
#    solver.add(c1_bytes[i] == c1[i])
#    solver.add(intermediate_state_end[i] == intermediate_state_start[i])

# if solver.check() == sat:
#       model = solver.model()
#       print(model)
#       print(f"correct intermediate value {[model[i] for i in intermediate_state_start]}")
# print("done")

#|   | plain    | 7d95d7d9ba564e419cada946087df33b | 7e95d7d9ba564e419cada946087df33b | 03000000000000000000000000000000 | xor'ed | 03000000000000000000000000000000 | NO     |
#|   | add keys | 3cd49698fb170f00ddece807493cb27a | 3fd49698fb170f00ddece807493cb27a | 03000000000000000000000000000000 | xored  | 03000000000000000000000000000000 | NO     |
#|   | shift    | 3c17e87afbecb298dd3c960049d40f07 | 3f17e87afbecb298dd3c960049d40f07 | 03000000000000000000000000000000 | xor'ed | 03000000000000000000000000000000 | shift  |
#|!  | sbox     | ebf09bda0fce3746c1eb90633b4876c5 | 75f09bda0fce3746c1eb90633b4876c5 | 9e000000000000000000000000000000 | xor'ed | 9e000000000000000000000000000000 |  1/2^16 |
#|!  | mix      | 877c43e2269765644cc4b4e51df4cbe2 | a0e2dd5b269765644cc4b4e51df4cbe2 | 279e9eb9000000000000000000000000 | xor'ed | 279e9eb9000000000000000000000000 |        |
#|!  | add keys | 44be8120a414e6e78f0676279f774861 | 63201f99a414e6e78f0676279f774861 | 279e9eb9000000000000000000000000 | xor'ed | 279e9eb9000000000000000000000000 |        |
#|!  | sbox     | 1bae0cb749fa8e94736f38ccdbf552ef | fbb7c0ee49fa8e94736f38ccdbf552ef | e019cc59000000000000000000000000 | xor'ed | e019cc59000000000000000000000000 |  1/2^16 |
#|   | shift    | 1bfa38ef496f52b773f50c94dbae8ecc | fbfa38ef496f52ee73f5c094dbb78ecc | e0000000000000590000cc0000190000 | xor'ed | e019cc59000000000000000000000000 | ishift |
#|   | mix      | f453bb2ac6d640937a02395f06d93dd5 | 2fb35b119f8fab21b64dba932deb24cc | dbe0e03b5959ebb2cc4f83cc2b321919 | xor'ed | e0000000000000590000cc0000190000 | imix   |
#|   | add keys | d97d95fb697bedc1166d56cfe835d1c6 | 029d75c030220673da22d503c307c8df | dbe0e03b5959ebb2cc4f83cc2b321919 | xor'ed | dbe0e03b5959ebb2cc4f83cc2b321919 |        |
#|   |          |                                  |                                  |                                  |        |                                  |        |
#|   |          |                                  |                                  |                                  |        |                                  |        |
  # Inverse MixColumns operation
#   for i in range(4):
#     a0, a1, a2, a3 = output_state[i::4]  # Get column elements
#     # Matrix multiplication with inverse MixColumns matrix
#     output_state[i] = mult14(a0) ^ mult11(a1) ^ mult13(a2) ^ mult9(a3)      # 14*a0 + 11*a1 + 13*a2 + 9*a3
#     output_state[i+4] = mult9(a0) ^ mult14(a1) ^ mult11(a2) ^ mult13(a3)    # 9*a0 + 14*a1 + 11*a2 + 13*a3
#     output_state[i+8] = mult13(a0) ^ mult9(a1) ^ mult14(a2) ^ mult11(a3)    # 13*a0 + 9*a1 + 14*a2 + 11*a3
#     output_state[i+12] = mult11(a0) ^ mult13(a1) ^ mult9(a2) ^ mult14(a3)   # 11*a0 + 13*a1 + 9*a2 + 14*a3
# for i in range(4):
#   a0, a1, a2, a3 = intermediate_state[i::4]
#   intermediate_state[i] = mult2(a0) ^ (mult2(a1) ^ a1) ^ a2 ^ a3        # 2*a0 + 3*a1 + a2 + a3
#   intermediate_state[i+4] = a0 ^ mult2(a1) ^ (mult2(a2) ^ a2) ^ a3      # a0 + 2*a1 + 3*a2 + a3
#   intermediate_state[i+8] = a0 ^ a1 ^ mult2(a2) ^ (mult2(a3) ^ a3)      # a0 + a1 + 2*a2 + 3*a3
#   intermediate_state[i+12] = (mult2(a3) ^ a3) ^ a0 ^ a1 ^ mult2(a2)      # 3*a3 + a0 + a1 + 2*a2

# for i in range(0,len(intermediate_state) - 1,4):
#   intermediate_state[i: i+ 4] = intermediate_state[i + i//4:i + 4] +  intermediate_state[i : i + i//4]



# for i in range(0,16-1,4):
#   c0_state[i: i+ 4] = c0_state[i + 4 - i//4: i + 4] + c0_state[i:i + 4 - i//4]
#   c1_state[i: i+ 4] = c1_state[i + 4 - i//4: i + 4] + c1_state[i:i + 4 - i//4]
# print("after inverse shift rows:")

# | plain    | 241d2cc711104f05beb283c82c7e0d8c | 271d2cc711104f05beb283c82c7e0d8c |  3000000000000000000000000000000 |   |
# | add keys | 655c6d8650510e44fff3c2896d3f4ccd | 665c6d8650510e44fff3c2896d3f4ccd |  3000000000000000000000000000000 |   |
# | shift    | 6551c2cd50f34c86ff3f6d446d5c0e89 | 6651c2cd50f34c86ff3f6d446d5c0e89 |  3000000000000000000000000000000 |   |
# | sbox     | 4dd125bd530d294416753c1b3c4aaba7 | 33d125bd530d294416753c1b3c4aaba7 | 7e000000000000000000000000000000 |   |
# | mix      | 4dd125bd530d294416753c1b3c4aaba7 | 33d125bd530d294416753c1b3c4aaba7 | 7e000000000000000000000000000000 |   |
# | add keys | 8e13e77fd18eaac7d5b7fed9bec92824 | f013e77fd18eaac7d5b7fed9bec92824 | 7e000000000000000000000000000000 |   |
# | sbox     | 197d94d23e19acc603a9bb35aedd3436 | 8c7d94d23e19acc603a9bb35aedd3436 | 95000000000000000000000000000000 |   |
# | shift    | 1919bb363ea934d203dd94c6ae7dac35 | 8c19bb363ea934d203dd94c6ae7dac35 | 95000000000000000000000000000000 |   |
# | mix      | 1919bb363ea934d203dd94c6ae7dac35 | 8c19bb363ea934d203dd94c6ae7dac35 | 95000000000000000000000000000000 |   |
# | add keys | 343795e7910499806fb2fb5640914026 | a13795e7910499806fb2fb5640914026 | 95000000000000000000000000000000 |   |
# |          |                                  |                                  |                                0 |   |
# |          |                                  |                                  |                                0 |   |

