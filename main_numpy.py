import math
import os
import pickle
import random
from datetime import datetime

import numpy as np

from attacks.attack_numpy import Attack
from email_extraction import extract_sent_mail_contents, KeywordExtractor, extract_apache_ml, extract_wiki
from util import generate_matrix


def applyPadding(occ_matrix, n=500):
    for k_j in range(occ_matrix.shape[1]):
        nr_files = sum(occ_matrix[:, k_j])
        nr_fake_files_to_add = int(math.ceil(nr_files / n) * n - nr_files)
        possible_fake_files = list(np.argwhere(occ_matrix[:, k_j] == 0).flatten())
        if len(possible_fake_files) < nr_fake_files_to_add:
            # We need more documents to generate enough fake entries, so we generate fake document IDs
            fake_files = np.zeros((nr_fake_files_to_add - len(possible_fake_files), len(all_keywords)))
            occ_matrix = np.concatenate((occ_matrix, fake_files))
            possible_fake_files = list(np.argwhere(occ_matrix[:, k_j] == 0).flatten())

        new_fake_files = random.sample(possible_fake_files, nr_fake_files_to_add)
        occ_matrix[new_fake_files, k_j] = 1
    return occ_matrix


def applyObfuscation(occ_matrix, m=6, p=0.88703, q=0.04416):
    occ_matrix = np.repeat(occ_matrix, m, axis=0)

    for d_i in range(occ_matrix.shape[0]):
        for k_j in range(occ_matrix.shape[1]):
            if occ_matrix[d_i, k_j]:  # Document i contains keyword j
                if random.random() < p:
                    occ_matrix[d_i, k_j] = 0
            else:
                if random.random() < q:
                    occ_matrix[d_i, k_j] = 1

    return occ_matrix


def applyVolumeHiding(file_dictionary):
    max_volume = 0
    for file in file_dictionary.keys():
        max_volume = max(max_volume, file_dictionary[file]['volume'])

    for file in file_dictionary.keys():
        file_dictionary[file]['volume'] = max_volume

    return file_dictionary


maildir = {
    'enron': 'C:/Users/Steven/Documents/git/SSE_attacks/keyword_generation/maildir',
    'lucene': 'C:/Users/Steven/Documents/git/SSE_attacks/keyword_generation/apache_ml',
    'wiki': 'C:/Users/Steven/Documents/git/SSE_attacks/keyword_generation/wiki_plaintext'
}

countermeasures = {
    'padding': applyPadding,
    'obfuscation': applyObfuscation,
    'volume': applyVolumeHiding,
}

if __name__ == '__main__':
    # The number of keywords
    nr_keywords = 5000
    # Automate the runs for each leakage percentage
    percentages_leaked = [0.1, 0.5, 1, 5, 10, 30]

    countermeasure = ['padding']  # / obfuscation / padding / volume

    countermeasure_prefix = "_[" + ','.join(countermeasure) + "]" if len(countermeasure) > 0 else ''

    # Nr of runs
    runs = 20

    # Run the attack on a specific dataset, file locations defined above
    dataset = 'enron'  # enron / lucene / wiki

    # File to store the pickles, such that we don't have to extract the words every run
    pickle_file = f'./pickles/numpy/{dataset}_{nr_keywords}{countermeasure_prefix}.pkl'

    # Write the results to a document to create graphs later
    output_file = f'results/accuracy{countermeasure_prefix}_{dataset}_{datetime.today().strftime("%Y-%m-%d %H.%M.%S")}.txt'

    # Used to write metadata to the result file
    first = True
    for percentage_leaked in percentages_leaked:
        i = 0
        while i < runs:
            print(f"Attack for {percentage_leaked}% leakage; run {i + 1}/{runs}")

            if not os.path.isfile(pickle_file):
                # Extract data from the files
                if dataset == 'lucene':
                    files = extract_apache_ml(maildir[dataset])
                elif dataset == 'wiki':
                    files = extract_wiki(maildir[dataset])
                else:
                    files = extract_sent_mail_contents(maildir=maildir[dataset])

                # Extract keywords from the data
                keywordExtractor = KeywordExtractor(files, nr_keywords)

                all_keywords = keywordExtractor.get_sorted_keywords()
                all_files = keywordExtractor.files

                # "Encrypt" the queries and the server files
                queries = [kw + "_HASH" for kw in all_keywords]
                server_files = {
                    file + "_ENC": {'keywords': [kw + "_HASH" for kw in content['keywords']],
                                    'volume': content['volume']} for file, content in all_files.items()}

                # Generate matrix B and M of observed server data
                B = generate_matrix(server_files, queries)

                if len(countermeasure) > 0:
                    for c in countermeasure:
                        if c == 'volume':
                            server_files = applyVolumeHiding(server_files)
                        else:
                            B = countermeasures[c](B.T).T

                M = B.T.dot(B)

                del files
                del keywordExtractor

                # Store the data
                with open(pickle_file, 'wb') as file:
                    pickle.dump(all_files, file)
                    pickle.dump(all_keywords, file)
                    pickle.dump(queries, file)
                    pickle.dump(server_files, file)
                    pickle.dump(B, file)
                    pickle.dump(M, file)
                    print("Done dumping")

            else:
                # Open the stored data
                with open(pickle_file, 'rb') as file:
                    all_files = pickle.load(file)
                    all_keywords = pickle.load(file)
                    queries = pickle.load(file)
                    server_files = pickle.load(file)
                    B = pickle.load(file)
                    M = pickle.load(file)

            # Select known files based on the leakage percentage
            known_files = dict(random.sample(list(all_files.items()), round(len(all_files) * percentage_leaked / 100)))
            # Extract the known keywords from the leaked files
            known_keywords = list(set([keyword for content in known_files.values() for keyword in content['keywords']]))

            # Generate matrix A_ and M_ from the leaked data
            A_ = generate_matrix(known_files, known_keywords)
            M_ = A_.T.dot(A_)

            # Assert that the number of keywords in each known file are equal to the number queries in the corresponding
            # server file
            if not countermeasure:
                assert all([sum(A_[:, i]) == sum(B[:, list(server_files.keys()).index(file + "_ENC")]) for i, file in
                            enumerate(known_files)])

            # Initialize and start the attack
            attack = Attack(queries, list(known_files.keys()), known_keywords, list(server_files.keys()), A_, M_, B, M,
                            known_files, server_files)
            query_map, file_map = attack.attack()

            if len(countermeasure) > 0:
                # Only take the correct matches when using countermeasures
                query_map = {query: keyword for query, keyword in query_map.items() if query.rsplit('_', 1)[0] == keyword}
            # Calculate the query accuracy by "decrypting" the query and check for keyword equality
            query_acc = np.mean([query.rsplit('_', 1)[0] == keyword for query, keyword in query_map.items()]) * 100
            query_acc = 0 if math.isnan(query_acc) else query_acc
            print(len(query_map), '/', len(known_keywords), 'queries recovered with ->', str(query_acc) + '%')


            if len(countermeasure) > 0:
                # Only take the correct matches when using countermeasures
                file_map = {efile: file for efile, file in file_map.items() if efile.rsplit('_', 1)[0] == file}
            # Calculate the file accuracy by "decrypting" the encrypted file name and check for actual file equality
            file_acc = np.mean([efile.rsplit('_', 1)[0] == file for efile, file in file_map.items()]) * 100
            file_acc = 0 if math.isnan(file_acc) else file_acc
            print(len(file_map), '/', len(known_files), 'files recovered with ->', str(file_acc) + '%')

            if len(query_map) > 0:
                i += 1
            else:
                continue

            # Write the metadata to the output file
            if first:
                first = False
                with open(output_file, 'w') as file:
                    file.write(f"Dataset:\t{dataset}\n")
                    file.write(f"Number of files:\t{len(server_files)}\n\n")

            # Write the experiment results to the output file
            with open(output_file, 'a') as file:
                file.write(f"Percentage leaked:\t{percentage_leaked}\t"
                           f"Known files:\t{len(known_files)}\t"
                           f"Files recovered:\t{len(file_map)}\t"
                           f"Accuracy:\t{file_acc}%\t"
                           f"Nr keywords:\t{len(known_keywords)}\t"
                           f"Queries recovered:\t{len(query_map)}\t"
                           f"Percentage recovered:\t{len(query_map) / len(known_keywords) * 100}%\t"
                           f"Accuracy:\t{query_acc}%\n")
