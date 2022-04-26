# VAL-Attack
Volume and Access Pattern Leakage-Abuse Attack with Leaked Documents

This repo contains the implementation used to show the results in _Volume and Access Pattern Leakage-Abuse Attack with Leaked Documents_

## Basis
Everything used in the experiment is present here.
There are a number of files:
- `main_numpy.py`: Python script to simulate attacks with specified parameters, such as: dataset, number of keywords, leakage percentages and number of runs.
- `main_pandas.py`: Python script equal to `main_numpy.py` but written to use Pandas DataFrame.
- `email_extraction.py`: Python script to extract keywords from the given dataset
- `create_graphs.py`: Python script to create the plots from the result of an experiment.
- `util.py`: Python script with standard functions, like `generate_matrix` 
- `attacks`: Folder containing the attack
  - `attack_numpy.py`: Python script written to use Numpy arrays.
  - `attack_pandas.py`: Python script written to use Pandas DataFrame.
- `examples`: Folder containing small examples to test the attacks
  - `example_numpy.py`: Python script written to use Numpy arrays.
  - `example_pandas.py`: Python script written to use Pandas DataFrame.
- `pickles`: Folder used to store the .pkl files to save time in experiment runs
- `plots`: Folder used to store the graphical figures made by `create_graphs.py`
- `results`: Folder that stores the results from the VAL attack, LEAP attack and the Subgraph<sub>vol</sub> attack.
- `lucene.sh`: Script that downloads the files from the Apache Lucene mailing list

## Requirements
- Python 3.9
- pip
- Enron dataset: available from https://www.cs.cmu.edu/~enron/enron_mail_20150507.tar.gz
- Lucene dataset: available via `lucene.sh`
- Wikipedia dataset: https://dumps.wikimedia.org/simplewiki/20220401/simplewiki-20220401-pages-meta-current.xml.bz2 extracted via the tool from David Shapiro available via https://github.com/daveshap/PlainTextWikipedia 