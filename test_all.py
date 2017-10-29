import unittest
import set1,set2

sets = [set1,set2]

def crypto_test_true(exObj):
    report,success = exObj.check_result()
    return(success)

class TestCryptoExercises(unittest.TestCase):
    def setUp(self):
        self.sets = sets

    def test_all_true(self):
        for s in sets:
            d = s.__dict__
            for k,v in d.items():
                if 'Ex' in k:
                    o = d[k]()
                    report,success = o.check_result()
                    self.assertTrue(success,msg="Failed at set: {s} exercise: {e} report: {r}".format(s=s.__name__,e=k,r=report))

if __name__ == '__main__':
    unittest.main()


