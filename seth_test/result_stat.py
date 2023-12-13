#!/bin/python3
import statistics

with open("results.txt", "r") as f:
        lines = f.readlines()

vector = [int(line.strip()) for line in lines]

avg = statistics.mean(vector)
pstd = statistics.pstdev(vector)
minimum = min(vector)
maximum = max(vector)
median = sorted(vector)[len(vector) // 2]
num_samples = len(vector)
unique = len(set(vector))
num_outliers = sum(i > avg * 2 for i in vector)


# remove outliers from vector which are more than 5x the avg
vector = [i for i in vector if i <= avg * 5]


print(f"average: {avg}, pstd: {pstd}, min: {minimum}, max: {maximum}, median: {median}, num_samples: {num_samples}, unique: {unique}, num_outliers: {num_outliers}")
print("value: number of occurrences")
for i in sorted(set(vector)):
        print(f"{i}: {vector.count(i)}")
