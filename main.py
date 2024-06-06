from fastapi import FastAPI, HTTPException
from pydantic import BaseModel
from base64 import b64decode, b64encode
import random
import hashlib

app = FastAPI()

exported_algorithm = "RSA"
exported_bits = 3584
exported_private = "c+tv+jeHc5EE1NKzGXsX9YHjaD4owvavMkyJtg/E3XtY58/ms84LAkTo9ygLrwN2MuUYzMOaawMnoDTpHX6dAdyQwx+4V80MDo0YVL8i619YXSLPyMQJqNM9dscdb9P3KahvxHZ4Ec+lpLFhbRRXtbIvQw/ZkPp8nH7gRhnCP1WmdIu6QKneIxtZwZCgHOEU1UJCIMtPwuAnnYUs3F02bHsvvBnaXroJMMdfJIeroI5nBVePF4pUER0Ze77XwfUikLiezGvzBSTAIHsP1iYof/VTjaxzfDpgRkctaaqLP2wEZ2hy9QvSUPHw3i+oDu6bCn9BedZckkmyxlF3VEkgQDarI7m9csy57VRGJNCT4x9DBUvcL8Wyp8vXR8UfiuXHx6dP+8+1UlZ8V7tuaIZjp8R4TUjQo3GXBOaqy+zOJDiQg0eDUCDfxj50RXFFMoTqV2X9ZnPDdv0sWzXGUR1VQAq21aGn8fkE40nvndJdH/a4kf3NCFLYRp8wEe1L3x4O5THUaWSYQD+3NNA9Co3FIGNztVDBRyRpBvn4EoYEIH9G52IImhLMZqEnMyogZ2Bj5muBciLiO+xFpS1DygqYJQ=="
exported_modulus = "78CQC9LeLpZi2oil4UTaXVwmDaJGeWxZXKf6qBJhEkz65TVZlf46rCGJtR2ZqdrD97itCQ9RvY3+dbc3+5pSS/jABQuSq7kIX+xoTIUsArNWBXBIGAJpNkYpGzDKe+1o+95OSwHvaG9r5em8NF3JpQeDXe14x656tk6dd9H8FRoBMoDiDeF3v0AldjUPd6K/5UywcC5H+C3HmxVOtc+Yy8xcUkHdLyDTC/xY/2qzb9q0LSJUzmoTC7tp9pUeW/62KiZW01pwrctJXAFkZEK4yMttBLGmoqVRKLjQL+Rgi0iy3sUihdTYArIc7tu9LYiKHdRGCUppsl4+Qgt7jybuEtKVlxBpMbos46SZHMRtZ+Tuy/K7/FZRx03u9RKAFNrFJNfn/3p+TBf0DuAM7iJRH3JE3NFYq7TcnNQlAVJLVCS5JXcJAjNU8QPSpfrmgU0/3F0OweJ/UjBoEyFZmJvEfqXOdvVEKAub161/VIpVPczW88rVq8RLX1Oo0Bn5BQ09Tw2meJPDbrc7TtILfAW8Po0b35Sxi9SLklUywjQlSl/t7ku1mGioWIkD074gfE5IVV6m3ttq9bJuamX9Zj7cHQ=="
exported_product_code = "UpaEOY1ovcE="

class Params(BaseModel):
    user_name: str
    email: str
    hwid: str
    expire_date: dict
    maxbuild_date: dict
    time_limit: int
    user_data: str

def base10_encode(data):
    result = 0
    for byte in data:
        result = result * 256 + byte
    return result

def base10_decode(number):
    result = bytearray()
    while number > 0:
        result.append(number % 256)
        number //= 256
    return bytes(result[::-1])

def powmod(base, exp, mod):
    return pow(base, exp, mod)

def pack_serial(params):
    serial = []
    serial.extend([1, 1])
    if 'user_name' in params:
        user_name = params['user_name']
        if len(user_name) > 255:
            raise HTTPException(status_code=400, detail="User name is too long")
        serial.append(2)
        serial.append(len(user_name))
        serial.extend(ord(c) for c in user_name)
    if 'email' in params:
        email = params['email']
        if len(email) > 255:
            raise HTTPException(status_code=400, detail="E-Mail is too long")
        serial.append(3)
        serial.append(len(email))
        serial.extend(ord(c) for c in email)
    if 'hwid' in params:
        hwid = b64decode(params['hwid'])
        len_hwid = len(hwid)
        if len_hwid == 0:
            raise HTTPException(status_code=400, detail="HWID is empty")
        if len_hwid > 255:
            raise HTTPException(status_code=400, detail="HWID is too long")
        if len_hwid % 4 != 0:
            raise HTTPException(status_code=400, detail=f"Invalid HWID (not multiple of 4): {len_hwid}")
        serial.append(4)
        serial.append(len_hwid)
        serial.extend(hwid)
    if 'expire_date' in params:
        expire_date = params['expire_date']
        y, m, d = expire_date['year'], expire_date['month'], expire_date['day']
        if not (1 <= m <= 12 and 1 <= d <= 31 and y > 0):
            raise HTTPException(status_code=400, detail=f"Date of expiration is invalid: y={y} m={m} d={d}")
        serial.append(5)
        serial.extend([d, m, y % 256, y // 256])
    if 'time_limit' in params:
        limit = params['time_limit']
        if limit < 0 or limit > 255:
            raise HTTPException(status_code=400, detail=f"Running time limit is incorrect: {limit}")
        serial.append(6)
        serial.append(limit)
    if 'product_code' in params:
        pc = b64decode(params['product_code'])
        if len(pc) != 8:
            raise HTTPException(status_code=400, detail=f"Product code has invalid size: {len(pc)}")
        serial.append(7)
        serial.extend(pc)
    if 'user_data' in params:
        data = b64decode(params['user_data'])
        len_data = len(data)
        if len_data > 255:
            raise HTTPException(status_code=400, detail=f"User data is too long: {len_data}")
        serial.append(8)
        serial.append(len_data)
        serial.extend(data)
    if 'maxbuild_date' in params:
        maxbuild_date = params['maxbuild_date']
        y, m, d = maxbuild_date['year'], maxbuild_date['month'], maxbuild_date['day']
        if not (1 <= m <= 12 and 1 <= d <= 31 and y > 0):
            raise HTTPException(status_code=400, detail=f"Date of max build is invalid: y={y} m={m} d={d}")
        serial.append(9)
        serial.extend([d, m, y % 256, y // 256])
    return serial

@app.post("/generate_serial")
def generate_serial(params: Params):
    if exported_algorithm != "RSA":
        raise HTTPException(status_code=400, detail=f"Unsupported key generation algorithm: {exported_algorithm}")

    params_dict = params.dict()
    params_dict["product_code"] = exported_product_code
    serial = pack_serial(params_dict)
    serial_bin = bytearray(serial)
    hash1 = hashlib.sha1(serial_bin).digest()
    serial_bin.append(255)
    serial_bin.extend(hash1[:4][::-1])

    padding_front = [0, 2]
    size = random.randint(8, 16)
    padding_front.extend(random.randint(1, 255) for _ in range(size))
    padding_front.append(0)

    content_size = len(serial_bin) + len(padding_front)
    rest = exported_bits // 8 - content_size
    if rest < 0:
        raise HTTPException(status_code=400, detail=f"Content is too big to fit in key: {content_size}, maximal allowed is: {exported_bits // 8}")

    padding_back = [random.randint(0, 255) for _ in range(rest)]

    serial_final = bytearray(padding_front) + serial_bin + bytearray(padding_back)

    n = base10_encode(b64decode(exported_modulus))
    d = base10_encode(b64decode(exported_private))
    serial_final_number = base10_encode(serial_final)
    res_number = powmod(serial_final_number, d, n)
    res_bytes = base10_decode(res_number)
    res_b64 = b64encode(res_bytes).decode('utf-8')

    return {"serial": res_b64}
