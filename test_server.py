import ctypes
import os
import unittest

# Загрузка библиотеки
lib = ctypes.CDLL('./libserver.so')

# Определение сигнатур функций
lib.find_signatures.argtypes = [ctypes.c_char_p, ctypes.c_char_p, ctypes.c_int, ctypes.POINTER(ctypes.POINTER(ctypes.c_int)), ctypes.POINTER(ctypes.c_int), ctypes.POINTER(ctypes.c_int)]
lib.move_to_quarantine.argtypes = [ctypes.c_char_p, ctypes.POINTER(ctypes.c_int)]

class TestServerFunctions(unittest.TestCase):

    def setUp(self):
        # Создание каталога карантина
        quarantine_dir = os.path.abspath('./quarantine')
        if not os.path.exists(quarantine_dir):
            os.mkdir(quarantine_dir)

    def tearDown(self):
        # Очистка каталога карантина
        quarantine_dir = os.path.abspath('./quarantine')
        for f in os.listdir(quarantine_dir):
            os.remove(os.path.join(quarantine_dir, f))

    def test_find_signatures(self):
        file_path = os.path.abspath('testfile.txt').encode()
        signature = b'abcd'
        sig_len = len(signature)
        offsets = ctypes.POINTER(ctypes.c_int)()
        count = ctypes.c_int()
        res_error = ctypes.c_int()

        # Создаем тестовый файл
        with open(file_path, 'wb') as f:
            f.write(b'1234abcd5678abcd')

        print(f"Test file created at: {file_path.decode()}")

        lib.find_signatures(file_path, signature, sig_len, ctypes.byref(offsets), ctypes.byref(count), ctypes.byref(res_error))

        self.assertEqual(res_error.value, 0)
        self.assertEqual(count.value, 2)
        self.assertEqual(offsets[0], 4)
        self.assertEqual(offsets[1], 12)

        os.remove(file_path.decode())

    def test_find_signatures_no_matches(self):
        file_path = os.path.abspath('testfile.txt').encode()
        signature = b'xyz'
        sig_len = len(signature)
        offsets = ctypes.POINTER(ctypes.c_int)()
        count = ctypes.c_int()
        res_error = ctypes.c_int()

        # Создаем тестовый файл
        with open(file_path, 'wb') as f:
            f.write(b'1234abcd5678abcd')

        print(f"Test file created at: {file_path.decode()}")

        lib.find_signatures(file_path, signature, sig_len, ctypes.byref(offsets), ctypes.byref(count), ctypes.byref(res_error))

        self.assertEqual(res_error.value, 0)
        self.assertEqual(count.value, 0)

        os.remove(file_path.decode())

    def test_find_signatures_file_error(self):
        file_path = os.path.abspath('nonexistentfile.txt').encode()
        signature = b'abcd'
        sig_len = len(signature)
        offsets = ctypes.POINTER(ctypes.c_int)()
        count = ctypes.c_int()
        res_error = ctypes.c_int()

        lib.find_signatures(file_path, signature, sig_len, ctypes.byref(offsets), ctypes.byref(count), ctypes.byref(res_error))

        self.assertNotEqual(res_error.value, 0)
        self.assertEqual(count.value, 0)

    def test_move_to_quarantine(self):
        file_path = os.path.abspath('testfile.txt').encode()
        res_error = ctypes.c_int()

        # Создаем тестовый файл
        with open(file_path, 'wb') as f:
            f.write(b'Test content')

        print(f"Test file created at: {file_path.decode()}")

        lib.move_to_quarantine(file_path, ctypes.byref(res_error))

        self.assertEqual(res_error.value, 0)

        new_path = os.path.join(os.path.abspath('./quarantine'), os.path.basename(file_path.decode()))
        print(f"Checking new path: {new_path}")
        self.assertTrue(os.path.exists(new_path))

        os.remove(new_path)

    def test_move_to_quarantine_error(self):
        file_path = os.path.abspath('nonexistentfile.txt').encode()
        res_error = ctypes.c_int()

        lib.move_to_quarantine(file_path, ctypes.byref(res_error))

        self.assertNotEqual(res_error.value, 0)

if __name__ == '__main__':
    unittest.main()
