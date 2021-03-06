import matplotlib.pyplot as plt
import numpy as np


# Read the accuracy, depending on the result file
def get_accuracy(file_name, percentage):
    acc = {percentage: {'queries': [], 'files': []} for percentage in leaked_percentages}
    with open('./results/' + file_name, 'r') as f:
        file_content = f.readlines()
        for line in file_content:
            if line.startswith('Percentage leaked'):
                line_split = line.split('\t')

                total_keywords = int(line_split[9])
                recovered_keywords = int(line_split[11])

                known_files = int(line_split[3])
                recovered_files = int(line_split[5])

                leakage_percentage = float(line_split[1])
                if leakage_percentage in leaked_percentages:
                    if percentage:
                        acc[leakage_percentage]['files'].append(recovered_files / known_files * 100)
                        acc[leakage_percentage]['queries'].append(recovered_keywords / total_keywords * 100)
                    else:
                        acc[leakage_percentage]['queries'].append(recovered_keywords)
                        acc[leakage_percentage]['files'].append(recovered_files)

    # Take the average and error for each leakage percentage for the queries and files recovered
    for percentage in leaked_percentages:
        average_queries = np.mean(acc[percentage]['queries'])
        error_queries = np.std(acc[percentage]['queries'])

        average_files = np.mean(acc[percentage]['files'])
        error_files = np.std(acc[percentage]['files'])
        acc[percentage] = {'average_queries': average_queries, 'error_queries': error_queries,
                           'average_files': average_files, 'error_files': error_files}

    return acc


# Read the accuracy, depending on the result file
def get_accuracy_subgraph(file_name, percentage):
    acc = {percentage: {'queries': []} for percentage in leaked_percentages}
    with open('./results/' + file_name, 'r') as f:
        file_content = f.readlines()

        leakage_percentage = 0
        for line in file_content:
            if line.startswith('====  Attacks of '):
                line_split = line.split('Attacks of ')
                leakage_percentage = float(line_split[1].split('%')[0])

            if line.startswith('Know '):
                line_split = line.split("Know ")

                total_keywords = int(line_split[1].split('/')[1].split(' ')[0])
                recovered_keywords = int(line_split[1].split('/')[0])

                if leakage_percentage in leaked_percentages:
                    if percentage:
                        acc[leakage_percentage]['queries'].append(recovered_keywords / total_keywords * 100)
                    else:
                        acc[leakage_percentage]['queries'].append(recovered_keywords)

    # Take the average and error for each leakage percentage
    for percentage in leaked_percentages:
        average_queries = np.mean(acc[percentage]['queries']) if len(acc[percentage]['queries']) > 0 else 0
        error_queries = np.std(acc[percentage]['queries']) if len(acc[percentage]['queries']) > 0 else 0

        acc[percentage] = {'average_queries': average_queries, 'error_queries': error_queries}

    return acc


# Plot the results, depending on the datasets and output
def plot(datasets, percentage=False, part='files', countermeasures=False):
    # Create a figure with multiple axes
    fig, ax = plt.subplots()

    x = leaked_percentages
    prefix = '%' if percentage else '#'

    for dataset in datasets:
        # Our result file
        if countermeasures:
            for c in [['padding'], ['obfuscation'], ['volume hiding'], ['padding', 'volume hiding']]:
                countermeasure_prefix = ','.join(c)
                file_name = f"accuracy_[{countermeasure_prefix}]_{dataset}.txt"

                # Get the accuracy for our results
                acc = get_accuracy(file_name, percentage)

                # Plot the files recovered
                y = np.array([acc[key][f'average_{part}'] for key in x])
                error = [acc[key][f'error_{part}'] for key in x]

                ax.plot(x, y, color=colors[countermeasure_prefix][0], label=f'{countermeasure_prefix}')
                ax.fill_between(x, np.clip(y - error, 0, 100) if percentage else y - error,
                                np.clip(y + error, 0, 100) if percentage else y + error, alpha=0.5,
                                edgecolor=colors[countermeasure_prefix][0], facecolor=colors[countermeasure_prefix][1])
        else:
            file_name = f"accuracy_{dataset}.txt"

            # Get the accuracy for our results
            acc = get_accuracy(file_name, percentage)

            # Plot the files recovered
            y = np.array([acc[key][f'average_{part}'] for key in x])
            error = [acc[key][f'error_{part}'] for key in x]

            ax.plot(x, y, color=colors[dataset][0],
                    label=f'{prefix}recovered {part} {dataset.title() if not compare else "VAL"}')
            ax.fill_between(x, np.clip(y - error, 0, 100) if percentage else y - error,
                            np.clip(y + error, 0, 100) if percentage else y + error, alpha=0.5,
                            edgecolor=colors[dataset][0], facecolor=colors[dataset][1])

            # Compare with the LEAP attack and the Subgraph_vol attack
            if compare:
                # LEAP
                file_name = f"./leap/accuracy_{dataset}.txt"
                acc = get_accuracy(file_name, percentage)

                # Plot the files recovered
                y = np.array([acc[key][f'average_{part}'] for key in x])
                error = [acc[key][f'error_{part}'] for key in x]

                ax.plot(x, y, color='#3F7F4C', label=f'{prefix}recovered {part} LEAP')
                ax.fill_between(x, np.clip(y - error, 0, 100) if percentage else y - error,
                                np.clip(y + error, 0, 100) if percentage else y + error, alpha=0.5,
                                edgecolor='#3F7F4C', facecolor='#7EFF99')

                # The subgraph attack only recovers queries
                if part == 'queries':
                    # Subgraph
                    file_name = f"./subgraph_vol/accuracy_{dataset}.txt"
                    acc = get_accuracy_subgraph(file_name, percentage)

                    # Plot the queries recovered
                    y = np.array([acc[key]['average_queries'] for key in x])
                    error = [acc[key]['error_queries'] for key in x]

                    ax.plot(x, y, color='C1', label=f'{prefix}recovered {part} Subgraph_vol')
                    ax.fill_between(x, np.clip(y - error, 0, 100) if percentage else y - error,
                                    np.clip(y + error, 0, 100) if percentage else y + error, alpha=0.5,
                                    edgecolor='#fff530', facecolor='#ede998')

    ax.grid()
    ax.set_xlabel("Leakage (%)")
    ax.set_ylabel(f"{prefix}Recovered {part}")
    plt.xlim([leaked_percentages[0], leaked_percentages[-1]])

    ax.legend(loc='lower right')

    title = f"Accuracy {'VAL ' if not compare else ''}{prefix}{part} recovered" \
            f"{' compared' if compare else ' countermeasures' if countermeasures else ''}"
    plt.tight_layout()
    fig.suptitle(title)
    plt.savefig(f'./plots/{title}', dpi=300, pad_inches=0)
    plt.show()


if __name__ == '__main__':
    compare = True
    leaked_percentages = [0.1, 0.5, 1, 5, 10]
    countermeasure = False

    colors = {'enron': ['#1B2ACC', '#089FFF'],
              'lucene': ['#3F7F4C', '#7EFF99'],
              'wiki': ['#FFA500', '#FAD6a5'],
              'padding': ['#1B2ACC', '#089FFF'],
              'obfuscation': ['#3F7F4C', '#7EFF99'],
              'volume hiding': ['#FFA500', '#FAD6a5'],
              "padding,volume hiding": ['F620FA', 'F6A8F7']
              }

    if countermeasure:
        leaked_percentages.append(30)
        data = ['enron']

        plot(data, part='files', countermeasures=countermeasure)
        plot(data, True, 'files', countermeasures=countermeasure)

        plot(data, part='queries', countermeasures=countermeasure)
        plot(data, True, 'queries', countermeasures=countermeasure)
    elif compare:
        leaked_percentages.append(30)
        data = ['enron']

        plot(data, part='files')
        plot(data, True, 'files')

        plot(data, part='queries')
        plot(data, True, 'queries')
    else:
        data = ['enron', 'lucene', 'wiki']

        plot(data, part='files')
        plot(data, True, 'files')

        plot(data, part='queries')
        plot(data, True, 'queries')
