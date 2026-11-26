import tempfile
from pathlib import Path
import unittest

from prepare_adult import parse_adult, synthetic_records, fields, write_records


class AdultPreparationTests(unittest.TestCase):
    row = b"39, State-gov, 77516, Bachelors, 13, Never-married, Adm-clerical, Not-in-family, White, Male, 2174, 0, 40, United-States, <=50K"

    def test_full_bytes_unknowns_duplicates_and_test_punctuation_retained(self):
        missing = self.row.replace(b"State-gov", b"?")
        text = b"|1x3 Cross validator\r\n\r\n" + self.row + b".  \r\n" + missing + b"\n" + self.row + b"\n" + self.row
        records, counts = parse_adult(text)
        self.assertEqual(counts, {"raw": 4, "missing": 1, "retained": 4})
        self.assertEqual(records, [self.row+b".  ", missing, self.row, self.row])
        with tempfile.TemporaryDirectory() as tmp:
            path = Path(tmp)/'records.csv'
            info = write_records(path, records)
            self.assertEqual(path.read_bytes(), b''.join(r+b'\n' for r in records))
            self.assertEqual(info['record_bytes_without_newlines'], sum(map(len, records)))
            self.assertEqual(info['reference_statistics'][0]['mean'], 39)

    def test_malformed_rows_not_silently_discarded(self):
        for row in (b"1,2", self.row.replace(b"<=50K", b"unknown"), self.row.replace(b"77516", b"bad")):
            with self.assertRaises(ValueError):
                parse_adult(row)

    def test_synthetic_full_records_reproducible_and_nested(self):
        source = [self.row, self.row.replace(b'39,', b'41,').replace(b'40,', b'44,').replace(b'State-gov',b'?')]
        short = synthetic_records(10, 3, source)
        long = synthetic_records(20, 3, source)
        self.assertEqual(short, long[:10])
        self.assertNotEqual(short, synthetic_records(10, 4, source))
        self.assertTrue(all(len(fields(r)) == 15 for r in long))
        self.assertTrue(any(r not in source for r in long))
        self.assertTrue(all(abs(len(r)-len(self.row)) < 10 for r in long))


if __name__ == "__main__":
    unittest.main()
