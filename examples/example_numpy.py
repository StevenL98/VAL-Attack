import numpy as np

from attacks.attack_numpy import Attack
from util import generate_matrix

keywords = ['Aap', 'Noot', 'Mies', 'Wim']

all_files = {
    "File_01": {'keywords': ['Aap', 'Noot', 'Mies', 'Wim'], 'volume': 200},
    "File_02": {'keywords': ['Aap', 'Mies'], 'volume': 220},
    "File_03": {'keywords': ['Aap'], 'volume': 200},
    "File_04": {'keywords': ['Aap'], 'volume': 200},
}

known_files = {
    "File_01": {'keywords': ['Aap', 'Noot', 'Mies', 'Wim'], 'volume': 200},
    "File_02": {'keywords': ['Aap', 'Mies'], 'volume': 220},
    "File_03": {'keywords': ['Aap'], 'volume': 200},
    # "File_04": {'keywords': ['Aap'], 'volume': 200},
}

known_keywords = list(set([keyword for content in known_files.values() for keyword in content['keywords']]))

queries = [kw + "_HASH" for kw in keywords]
server_files = {
    file + "_ENC": {'keywords': [kw + "_HASH" for kw in content['keywords']], 'volume': content['volume']} for
    file, content in all_files.items()}

A_ = generate_matrix(known_files, known_keywords)
M_ = np.dot(A_.T, A_)
B = generate_matrix(server_files, queries)
M = np.dot(B.T, B)

if __name__ == '__main__':
    attack = Attack(queries, list(known_files.keys()), known_keywords, list(server_files.keys()), A_, M_, B, M,
                    known_files, server_files)
    query_map, file_map = attack.attack()
    print(query_map, str(np.mean([query.split('_')[0] == keyword for query, keyword in query_map.items()]) * 100) + '%')
    print(file_map, str(np.mean([efile.rsplit('_', 1)[0] == file for efile, file in file_map.items()]) * 100) + '%')
