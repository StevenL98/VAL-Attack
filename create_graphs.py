import matplotlib.pyplot as plt
import numpy as np

attack_name = 'VAL'


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


def plot(percentage=False):
    # Our result file
    file_name = f"accuracy_{dataset}.txt"
    prefix = '%' if percentage else '#'

    # Get the accuracy for our results
    acc = get_accuracy(file_name, percentage)

    # Create a figure with multiple axes
    fig, ax = plt.subplots()
    ax2 = ax.twinx()

    # Set the x-axis to the leakage percentages
    x = acc.keys()

    # Plot the files recovered
    y = np.array([acc[key]['average_files'] for key in x])
    error = [acc[key]['error_files'] for key in x]

    ax.plot(x, y, color='#1B2ACC', label=f'{prefix}recovered files ' + attack_name)
    ax.fill_between(x, np.clip(y - error, 0, 100) if percentage else y - error,
                    np.clip(y + error, 0, 100) if percentage else y + error, alpha=0.5,
                    edgecolor='#1B2ACC', facecolor='#089FFF')

    # Plot the queries recovered
    y = np.array([acc[key]['average_queries'] for key in x])
    error = [acc[key]['error_queries'] for key in x]

    ax2.plot(x, y, color='#CC4F1B', label=f'{prefix}recovered queries ' + attack_name)
    ax2.fill_between(x, np.clip(y - error, 0, 100) if percentage else y - error,
                     np.clip(y + error, 0, 100) if percentage else y + error, alpha=0.5,
                     edgecolor='#CC4F1B', facecolor='#FF9848')

    # Compare with the LEAP attack and the Subgraph_vol attack
    if compare:
        # LEAP
        file_name = f"./leap/accuracy_{dataset}.txt"
        acc = get_accuracy(file_name, percentage)

        # Plot the files recovered
        y = np.array([acc[key]['average_files'] for key in x])
        error = [acc[key]['error_files'] for key in x]

        ax.plot(x, y, color='#3F7F4C', label=f'{prefix}recovered files LEAP')
        ax.fill_between(x, np.clip(y - error, 0, 100) if percentage else y - error,
                        np.clip(y + error, 0, 100) if percentage else y + error, alpha=0.5,
                        edgecolor='#3F7F4C', facecolor='#7EFF99')

        # Plot the queries recovered
        y = np.array([acc[key]['average_queries'] for key in x])
        error = [acc[key]['error_queries'] for key in x]

        ax2.plot(x, y, color='#fff530', label=f'{prefix}recovered queries LEAP')
        ax2.fill_between(x, np.clip(y - error, 0, 100) if percentage else y - error,
                         np.clip(y + error, 0, 100) if percentage else y + error, alpha=0.5,
                         edgecolor='#fff530', facecolor='#ede998')

        # Subgraph
        file_name = f"./subgraph_vol/accuracy_{dataset}.txt"
        acc = get_accuracy_subgraph(file_name, percentage)

        # Plot the queries recovered
        y = np.array([acc[key]['average_queries'] for key in x])
        error = [acc[key]['error_queries'] for key in x]

        ax.plot(x, y, color='C1', label=f'{prefix}recovered queries Subgraph_vol')
        ax.fill_between(x, np.clip(y - error, 0, 100) if percentage else y - error,
                        np.clip(y + error, 0, 100) if percentage else y + error, alpha=0.5,
                        edgecolor='#fff530', facecolor='#ede998')

    # Show a grid
    # ax.grid()
    # ax2.grid(linestyle='--')

    # Set the labels on all 3 axes
    ax.set_xlabel("Leakage (%)")
    ax.set_ylabel(f"{prefix}Recovered files")
    ax2.set_ylabel(f"{prefix}Queries recovered")

    # Limit the x-axis to the first and last leakage percentage
    plt.xlim([leaked_percentages[0], leaked_percentages[-1]])

    # Combine the legend for all 2 y-axis
    handles, labels = [(a + b) for a, b in zip(ax.get_legend_handles_labels(), ax2.get_legend_handles_labels())]
    ax.legend(handles, labels, loc='lower right')

    # Save the plot with an appropriate title
    fig.suptitle(f"{prefix}Files and {prefix}queries recovered for the {dataset} dataset")
    title = f'Attack {dataset}{" compared" if compare else ""}'
    plt.tight_layout()
    plt.savefig(f'./plots/Accuracy {"percentage " if percentage else ""}' + title, dpi=300, pad_inches=0)
    plt.show()


if __name__ == '__main__':
    dataset = 'enron'  # enron / lucene / wiki
    compare = True
    leaked_percentages = [0.1, 0.5, 1, 5, 10, 30]

    # We can't compare with the lucene or wiki database
    # Since we don't have data from the LEAP or Subgraph attack with this dataset
    if dataset != 'enron':
        compare = False

    # Plot actual numbers
    plot()
    # Plot percentages
    plot(True)
