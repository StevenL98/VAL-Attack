import numpy as np


class Attack:

    def __init__(self, queries, known_documents, known_keywords, encrypted_documents, A_, M_, B, M, known_docs_dict,
                 enc_docs_dict):
        self.known_documents = known_documents
        self.known_keywords = known_keywords
        self.encrypted_documents = encrypted_documents
        self.queries = queries
        self.known_documents_dict = known_docs_dict
        self.encrypted_documents_dict = enc_docs_dict

        print('m :', len(queries))
        print("m':", len(known_keywords))
        print("n :", len(encrypted_documents))
        print("n':", len(known_documents))

        # m′×n′ document-keyword matrix A′
        self.A_ = A_
        # n′×n′ d-occurrence matrix M′
        self.M_ = M_

        # m × n encrypted document-query matrix B
        self.B = B
        # n × n ed-occurrence matrix M
        self.M = M

        self.C = {}
        self.R = {}

        self.B_map = self.A_map = None

    def attack(self):
        # Extend the matrix A_ to matrix A_map by appending zeros
        extension = np.zeros((len(self.queries) - self.A_.shape[0], self.A_.shape[1]))
        self.A_map = np.vstack((self.A_, extension))
        self.B_map = self.B

        # Match documents based on unique number of keywords
        self._match_docs_unique_count()

        # Match documents based on unique number of keywords and volume pattern
        self._match_by_volume()

        # Match documents based on co-occurrence with already matched documents
        S = self._occurrence(self.C, self.M, self.M_, self.A_map, self.B_map)
        self.C |= S

        # Match documents based on unique number of keywords and volume pattern, again for maximizing the matched docs
        self._match_by_volume()

        size_C = len(self.C) - 1
        size_R = len(self.R) - 1
        # While C or R are growing
        while len(self.C) != size_C or len(self.R) != size_R:
            size_C = len(self.C)
            size_R = len(self.R)

            # Match keywords to queries, based on unique document occurrence
            self._match_keywords()

            # Match more documents based on unique number of keywords and volume pattern
            self._match_by_volume()

            # Match documents based on unique order of matched keywords
            self._match_docs_unique_order_keywords()

            # Match documents on unique, updated, number of keywords
            self._match_docs_unique_count_unmatched()

            # Match documents based on co-occurrence with already matched documents
            S = self._occurrence(self.C, self.M, self.M_, self.A_map, self.B_map)
            self.C |= S

        return self.R, self.C

    def _match_docs_unique_count(self):
        vector_B_dict = {}
        vector_A_dict = {}

        # Sum A and B beforehand, to reduce computing time
        sum_B = self.B_map.sum(axis=0)
        sum_A = self.A_map.sum(axis=0)

        # For each (observed/known) document store the number of keywords
        for j in range(len(self.encrypted_documents)):
            vector_Bj = sum_B[j]
            if vector_Bj in vector_B_dict:
                vector_B_dict[vector_Bj].append(j)
            else:
                vector_B_dict[vector_Bj] = [j]

        for j_ in range(len(self.known_documents)):
            vector_Aj = sum_A[j_]
            if vector_Aj in vector_A_dict:
                vector_A_dict[vector_Aj].append(j_)
            else:
                vector_A_dict[vector_Aj] = [j_]

        # If there are server documents with a unique number of keywords, match with the corresponding plaintext file
        for sum_bj, edocs in vector_B_dict.items():
            if len(edocs) == 1 and sum_bj in vector_A_dict:
                self.C[self.encrypted_documents[edocs[0]]] = self.known_documents[vector_A_dict[sum_bj][0]]

    def _match_keywords(self):
        # Take the columns from B and A with the matched documents
        Bc = self.B_map[:, [self.encrypted_documents.index(ed_j) for ed_j in self.C.keys()]]
        Ac = self.A_map[:, [self.known_documents.index(d_j) for d_j in self.C.values()]]

        # Store the file occurrence of each keyword
        Br_dict = {}
        for i, qi in enumerate(self.queries):
            if qi in self.R:
                continue
            row = tuple(Bc[i])
            if row in Br_dict:
                Br_dict[row].append(qi)
            else:
                Br_dict[row] = [qi]

        Ar_dict = {}
        for j, kj in enumerate(self.known_keywords):
            if kj in self.R.values():
                continue
            row = tuple(Ac[j])
            if row in Ar_dict:
                Ar_dict[row].append(kj)
            else:
                Ar_dict[row] = [kj]

        # Match the keywords with unique file occurrence pattern
        for row, queries in Br_dict.items():
            if len(queries) == 1 and row in Ar_dict:
                keyword = Ar_dict[row][0]
                query = queries[0]
                self.R[query] = keyword
            elif row in Ar_dict:
                # If the occurrence pattern is not unique, try matching with total occurrence in all (unmatched) files
                candidates = Ar_dict[row]

                server_sum = {qi: self.B_map[self.queries.index(qi)].sum() for qi in queries}
                server_sum = {k: v for k, v in sorted(server_sum.items(), key=lambda item: item[1], reverse=True)}
                known_sum = {kw: self.A_map[self.known_keywords.index(kw)].sum() for kw in candidates}
                known_sum = {k: v for k, v in sorted(known_sum.items(), key=lambda item: item[1], reverse=True)}

                known_sum_keys = list(known_sum.keys())
                server_sum_keys = list(server_sum.keys())

                if len(known_sum_keys) > 1 and len(server_sum_keys) > 1:
                    # If one of the candidates occurs more often than the others and the occurrence of the query is
                    # less than the second largest candidate, we have a match
                    if known_sum[known_sum_keys[1]] < known_sum[known_sum_keys[0]] > server_sum[server_sum_keys[1]]:
                        self.R[server_sum_keys[0]] = known_sum_keys[0]

    def _match_docs_unique_order_keywords(self):
        # Take the rows from B and A with the matched keywords
        Br = self.B_map[[self.queries.index(qj) for qj in self.R.keys()]]
        Ar = self.A_map[[self.known_keywords.index(kw) for kw in self.R.values()]]

        # Store the columns of each file
        Bc_dict = {}
        for i, ed_i in enumerate(self.encrypted_documents):
            column = tuple(Br[:, i])
            if column in Bc_dict:
                Bc_dict[column].append(ed_i)
            else:
                Bc_dict[column] = [ed_i]

        Ac_dict = {}
        for j, d_j in enumerate(self.known_documents):
            column = tuple(Ar[:, j])
            if column in Ac_dict:
                Ac_dict[column].append(d_j)
            else:
                Ac_dict[column] = [d_j]

        # Match the files with unique keyword occurrence pattern
        for column, edocs in Bc_dict.items():
            if len(edocs) == 1:
                enc_doc = edocs[0]
                if enc_doc not in self.C and column in Ac_dict:
                    known_doc = Ac_dict[column][0]
                    self.C[enc_doc] = known_doc

    def _match_docs_unique_count_unmatched(self):
        # Update matrix A and B, and set the matched rows to 0
        self.B_map[[self.queries.index(query) for query in self.R.keys()]] = 0
        self.A_map[[self.known_keywords.index(kw) for kw in self.R.values()]] = 0

        vector_B_dict = {}
        vector_A_dict = {}

        # Sum A and B beforehand, to reduce computing time
        sum_B = self.B_map.sum(axis=0)
        sum_A = self.A_map.sum(axis=0)

        # For each (observed/known) document store the number of keywords
        for j, ed_j in enumerate(self.encrypted_documents):
            if ed_j in self.C:
                continue

            vector_Bj = sum_B[j]
            if vector_Bj in vector_B_dict:
                vector_B_dict[vector_Bj].append(ed_j)
            else:
                vector_B_dict[vector_Bj] = [ed_j]

        for j, d_j in enumerate(self.known_documents):
            if d_j in self.C.values():
                continue

            vector_Aj = sum_A[j]
            if vector_Aj in vector_A_dict:
                vector_A_dict[vector_Aj].append(d_j)
            else:
                vector_A_dict[vector_Aj] = [d_j]

        # If there are server documents with a unique number of keywords, match with the corresponding plaintext file
        for sum_bj, edocs in vector_B_dict.items():
            if len(edocs) == 1 and sum_bj in vector_A_dict:
                enc_doc = edocs[0]
                known_doc = vector_A_dict[sum_bj][0]
                self.C[enc_doc] = known_doc

    def _occurrence(self, C, M, M_, A_, B):
        S = {1}
        C_ = C

        # Sum A and B beforehand, to reduce computing time
        sum_B = B.sum(axis=0)
        sum_A_ = A_.sum(axis=0)

        sum_B_dict = {}

        # For each observed document, store the number of keywords
        for j, ed_j in enumerate(self.encrypted_documents):
            if ed_j not in C.keys():
                sum_B_j = sum_B[j]
                if sum_B_j in sum_B_dict:
                    sum_B_dict[sum_B_j].append(ed_j)
                else:
                    sum_B_dict[sum_B_j] = [ed_j]

        while len(S) != 0:
            S = {}

            # For each leaked document
            for j_, d_j in enumerate(self.known_documents):
                if d_j in C_.values():
                    continue

                # Get the number of keywords for document j
                sum_Aj = sum_A_[j_]

                if sum_Aj not in sum_B_dict:
                    continue

                # And the server candidates with the same number of keywords as document j
                candidates = sum_B_dict[sum_Aj]

                candidates_copy = candidates.copy()

                # Loop over each candidate and check if they are still a match to document j
                for ed_j in candidates_copy:
                    if ed_j in self.C:
                        candidates.remove(ed_j)
                        continue
                    j = self.encrypted_documents.index(ed_j)
                    for ed_k, d_k in C_.items():
                        k = self.encrypted_documents.index(ed_k)
                        k_ = self.known_documents.index(d_k)
                        # If the co-occurrence of the candidate and document j is not equal, it is not a match
                        if M[j][k] != M_[j_][k_]:
                            candidates.remove(ed_j)
                            break

                # If there is only candidate left, it is a match
                if len(candidates) == 1:
                    S[candidates[0]] = d_j
                    C_ |= S

        # Return the matched documents
        return C_

    def _match_by_volume(self):
        # Store the volume and number of keywords beforehand, to reduce computing time
        A_dict = {}
        for d_j, content_j in self.known_documents_dict.items():
            if d_j in self.C.values():
                continue
            key_j = (content_j['volume'], len(content_j['keywords']))
            if key_j in A_dict:
                A_dict[key_j].append(d_j)
            else:
                A_dict[key_j] = [d_j]

        B_dict = {}
        for ed_j, enc_content_j in self.encrypted_documents_dict.items():
            if ed_j in self.C:
                continue
            key_j = (enc_content_j['volume'], len(enc_content_j['keywords']))
            if key_j in B_dict:
                B_dict[key_j].append(ed_j)
            else:
                B_dict[key_j] = [ed_j]

        # For each server document
        for key_j, enc_docs in B_dict.items():
            # If a document has a unique pattern, search for the plaintext file and match
            if len(enc_docs) == 1:
                if key_j in A_dict:
                    enc_doc = enc_docs[0]
                    known_doc = A_dict[key_j][0]
                    self.C[enc_doc] = known_doc
            # If multiple documents have the same pattern, try matching with matched keywords
            elif len(self.R) > 0 and key_j in A_dict:
                Br = self.B_map[[self.queries.index(qi) for qi in self.R.keys()]]
                Ar = self.A_map[[self.known_keywords.index(kw) for kw in self.R.values()]]

                # For each candidate file store the keyword occurrence pattern
                dict_B_ = {}
                for ed_j in enc_docs:
                    column = tuple(Br[:, self.encrypted_documents.index(ed_j)])
                    if column in dict_B_:
                        dict_B_[column].append(ed_j)
                    else:
                        dict_B_[column] = [ed_j]

                dict_A_ = {}
                for d_j in A_dict[key_j]:
                    column = tuple(Ar[:, self.known_documents.index(d_j)])
                    if column in dict_A_:
                        dict_A_[column].append(d_j)
                    else:
                        dict_A_[column] = [d_j]

                # Match if a keyword occurrence pattern is unique
                for column, enc_files in dict_B_.items():
                    if len(enc_files) == 1 and column in dict_A_:
                        enc_file = enc_files[0]
                        known_file = dict_A_[column][0]
                        self.C[enc_file] = known_file
