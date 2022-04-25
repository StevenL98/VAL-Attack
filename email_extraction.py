import email
import glob
import json
import mailbox
import multiprocessing
import os
from collections import Counter
from contextlib import contextmanager
from functools import reduce

import nltk
import tqdm
from nltk.corpus import stopwords
from nltk.stem.porter import PorterStemmer
from nltk.tokenize import sent_tokenize, word_tokenize


def get_body_from_enron_email(mail):
    msg = email.message_from_string(mail)
    parts = []
    for part in msg.walk():
        if part.get_content_type() == "text/plain":
            parts.append(part.get_payload())
    return "".join(parts)


def get_body_from_mboxmsg(msg):
    """Extract the content from a raw Apache email"""
    parts = []
    for part in msg.walk():
        if part.get_content_type() == "text/plain":
            parts.append(part.get_payload())
    body = "".join(parts)
    body = body.split("To unsubscribe")[0]  # at the end of each email of the mailing list.
    return body


def extract_sent_mail_contents(maildir):
    path = os.path.expanduser(maildir)
    mails = glob.glob(f"{path}/*/_sent_mail/*")
    mails = [mail.replace('\\', '/') for mail in mails]

    files = {}

    for mailfile_path in tqdm.tqdm(iterable=mails, desc="Reading the emails"):
        with open(mailfile_path, "r") as mailfile:
            content = {}
            raw_mail = mailfile.read()
            content['content'] = get_body_from_enron_email(raw_mail)
            content['volume'] = mailfile.tell()
            files[mailfile_path] = content

    return files


def extract_apache_ml(maildir):
    path = os.path.expanduser(maildir)
    mails = glob.glob(f"{path}/*")

    files = {}
    for mbox_path in tqdm.tqdm(iterable=mails, desc="Reading the emails"):
        for mail in mailbox.mbox(mbox_path):
            content = {}
            mail_content = get_body_from_mboxmsg(mail)
            content['content'] = mail_content
            content['volume'] = len(mail_content)
            file_name = mail["Message-ID"] if type(mail["Message-ID"]) == str else "file_" + str(len(files))
            files[file_name] = content

    return files


def extract_wiki(maildir):
    path = os.path.expanduser(maildir)
    files = glob.glob(f"{path}/*")

    files = files[:50000]

    result = {}
    for file in tqdm.tqdm(iterable=files, desc="Reading the wikipedia pages"):
        with open(file, "r", encoding='utf-8') as wiki_file:
            content = {}
            raw_file = json.load(wiki_file)
            content['content'] = raw_file['text']
            content['volume'] = wiki_file.tell()
            result[raw_file['id'] + "_" + raw_file['title']] = content

    return result


@contextmanager
def poolcontext(*args, **kwargs):
    """Context manager to standardize the parallelized functions."""
    pool = multiprocessing.Pool(*args, **kwargs)
    yield pool
    pool.terminate()


def chunk_dict(input_dict, chunks=2):
    "Splits dict by keys. Returns a list of dictionaries."
    # prep with empty dicts
    return_list = [dict() for idx in range(chunks)]
    idx = 0
    for k, v in input_dict.items():
        return_list[idx][k] = v
        if idx < chunks - 1:  # indexes start at 0
            idx += 1
        else:
            idx = 0
    return return_list


class KeywordExtractor:

    def __init__(self, file_dict, voc_size=100, min_freq=1, extraction_type='keywords'):
        NUM_CORES = multiprocessing.cpu_count()
        print(f"Extracting {extraction_type} from emails")
        with poolcontext(processes=NUM_CORES) as pool:
            results = pool.starmap(self.extract_email_keywords, enumerate(chunk_dict(file_dict, NUM_CORES)))
            freq_dict, glob_freq_dict = reduce(self._merge_results, results)

        # Creation of the keywords
        glob_freq_list = nltk.FreqDist(glob_freq_dict)
        del glob_freq_dict
        glob_freq_list = (glob_freq_list.most_common(voc_size) if voc_size else glob_freq_list.most_common())
        self.sorted_keywords_with_occ = sorted([(word, count) for word, count in glob_freq_list if count >= min_freq],
                                               key=lambda d: d[1], reverse=True)

        # Creation of the occurrence matrix
        self.freq_dict = freq_dict

        self.files = {file: {'keywords': [kw for kw in freq_dict[file] if kw in [tup[0] for tup in glob_freq_list]],
                             'volume': file_dict[file]['volume']} for file in file_dict.keys()}

        del glob_freq_list

    def get_sorted_keywords(self):
        return list(dict(self.sorted_keywords_with_occ).keys())

    @staticmethod
    def _merge_results(res1, res2):
        merge_results2 = Counter(res1[1]) + Counter(res2[1])

        merge_results1 = res1[0].copy()
        merge_results1.update(res2[0])
        return merge_results1, merge_results2

    @staticmethod
    def get_keywords_from_one_email(email_text, freq=False):
        stopwords_list = stopwords.words("english")
        stopwords_list.extend(["subject", "cc", "from", "to", "forward"])
        stemmer = PorterStemmer()

        stemmed_word_list = [stemmer.stem(word.lower()) for sentence in sent_tokenize(email_text) for word in
                             word_tokenize(sentence) if word.lower() not in stopwords_list and word.isalnum()]
        if freq:  # (word, occurrence) sorted list
            return nltk.FreqDist(stemmed_word_list)
        else:  # Word list
            return stemmed_word_list

    @staticmethod
    def extract_email_keywords(index, dictionary, one_occ_per_doc=True):
        freq_dict = {}
        glob_freq_list = {}
        for filename, content in dictionary.items():
            temp_freq_dist = KeywordExtractor.get_keywords_from_one_email(content['content'], freq=True)
            freq_dict[filename] = []
            for word, freq in temp_freq_dist.items():
                freq_to_add = 1 if one_occ_per_doc else freq
                freq_dict[filename].append(word)
                try:
                    glob_freq_list[word] += freq_to_add
                except KeyError:
                    glob_freq_list[word] = freq_to_add
        return freq_dict, glob_freq_list
