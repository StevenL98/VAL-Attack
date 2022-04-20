import multiprocessing

import numpy as np
from tqdm import tqdm

from email_extraction import poolcontext


def generate_matrix(files, keywords):
    occurrence_matrix = []
    keywords_per_file = [content['keywords'] for content in files.values()]
    if len(files) > 50:
        with poolcontext(processes=multiprocessing.cpu_count()) as pool:
            for row in tqdm(pool.map(OccRowComputer(keywords), keywords_per_file),
                            desc="Computing occurrence array", total=len(files)):
                occurrence_matrix.append(row)
    else:
        for kws in tqdm(keywords_per_file, desc="Computing occurrence array", total=len(files)):
            occurrence_matrix.append([int(kw in kws) for kw in keywords])

    return np.array(occurrence_matrix, dtype=np.float32).T


class OccRowComputer:
    """Callable class used to parallelize occurrence matrix computation"""

    def __init__(self, keywords):
        self.keywords = [word for word in keywords]

    def __call__(self, word_list):
        return [int(word in word_list) for word in self.keywords]
