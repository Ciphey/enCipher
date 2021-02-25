from src import enciphey
import base64
import binascii

obj = enciphey.encipher_crypto()


def test_base64():
    to_check = obj.Base64("Hello my name is bee")
    res = base64.b64decode(to_check)
    res = res.decode("utf-8")
    assert "Hello my name is bee" == res


def test_base32():
    text = "Since I've got lovely feet"
    res = base64.b32decode(obj.Base32(text))
    res = res.decode("utf-8")
    assert text == res


def test_base16():
    text = "It'd be so nice to have a friend"
    res = base64.b16decode(obj.Base16(text))


def test_morse():
    text = "hello my name is brandon\nand this is a cool feature (yes it is!)"
    res = obj.MorseCode(text)
    print(f"**** RES is {res}")
    MORSE_CODE_DICT = {
        "A": ".-",
        "B": "-...",
        "C": "-.-.",
        "D": "-..",
        "E": ".",
        "F": "..-.",
        "G": "--.",
        "H": "....",
        "I": "..",
        "J": ".---",
        "K": "-.-",
        "L": ".-..",
        "M": "--",
        "N": "-.",
        "O": "---",
        "P": ".--.",
        "Q": "--.-",
        "R": ".-.",
        "S": "...",
        "T": "-",
        "U": "..-",
        "V": "...-",
        "W": ".--",
        "X": "-..-",
        "Y": "-.--",
        "Z": "--..",
        "?": "..--..",
        ".": ".-.-.-",
        " ": "/",
        "0": "-----",
        "1": ".----",
        "2": "..---",
        "3": "...--",
        "4": "....-",
        "5": ".....",
        "6": "-....",
        "7": "--...",
        "8": "---..",
        "9": "----.",
        " ": "\n",
        "\n": " ",
    }
    CODE_REVERSED = {value: key for key, value in MORSE_CODE_DICT.items()}

    def from_morse(s):
        return "".join(CODE_REVERSED.get(i) for i in s.split())

    res = from_morse(res)
    assert res == text
