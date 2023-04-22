# Benchmark

The implementation provided by this project has been benchmarked to evaluate its performance.  
If you want to check the results yourself, you can run the benchmark by executing the following command:

```shell
# Compile and run the benchmark
./benchmark.sh [options]
```

It is suggested to run the benchmark multiple times and with different options to get a better idea of the performance of the library.

## Results

### Computer specifications

- OS: 6.2.11-arch1-1
- CPU: Intel(R) Core(TM) i5-8250U CPU @ 1.60GHz
- RAM: 8 GB
- Compiler: gcc 12.2.1 20230201

### Benchmark 1

- Max samples: 4000
- Max sampling time: 4
- Security level: 80
- Precompute enabled: no
- Hash type: sha1

| Operation     | Time (ms)             | Min (ms) | Max (ms) |
| ------------- | --------------------- | -------- | -------- |
| Setup         | 9.027689 (±4.516148 ) | 5.173207 | 25.0015  |
| ExtractP      | 2.446086 (±0.005016 ) | 2.440289 | 2.47422  |
| ExtractS      | 3.537366 (±0.006569 ) | 3.528269 | 3.55908  |
| Delegate      | 3.100255 (±0.018547 ) | 3.037263 | 3.13228  |
| DelVerify     | 4.121624 (±0.012236 ) | 4.113069 | 4.19752  |
| PKGen         | 1.106002 (±0.005634 ) | 1.094941 | 1.12163  |
| PSign         | 2.362325 (±0.016541 ) | 2.297568 | 2.39415  |
| SignVerify    | 6.604433 (±0.022728 ) | 6.557717 | 6.65807  |
| ImpPSign      | 3.100431 (±0.019073 ) | 3.038777 | 3.15021  |
| ImpSignVerify | 7.641981 (±0.066694 ) | 7.561166 | 7.88931  |

### Benchmark 2

- Max samples: 4000
- Max sampling time: 4
- Security level: 128
- Precompute enabled: no
- Hash type: sha256

| Operation     | Time (ms)                 | Min (ms)  | Max (ms)   |
| ------------- | ------------------------- | --------- | ---------- |
| Setup         | 218.499170 (±172.409853 ) | 69.592894 | 338.868217 |
| ExtractP      | 31.369141 (±0.041876 )    | 31.332701 | 31.509329  |
| ExtractS      | 37.454673 (±0.078655 )    | 37.412686 | 37.945949  |
| Delegate      | 22.315656 (±0.111793 )    | 22.124223 | 22.741206  |
| DelVerify     | 50.523667 (±0.257637 )    | 50.327337 | 51.738107  |
| PKGen         | 6.249678 (±0.009919 )     | 6.238745  | 6.291236   |
| PSign         | 17.707901 (±0.079850 )    | 17.465928 | 17.848110  |
| SignVerify    | 82.215506 (±0.175629 )    | 81.999108 | 82.789462  |
| ImpPSign      | 22.812475 (±0.154363 )    | 22.532718 | 23.267656  |
| ImpSignVerify | 83.607492 (±0.316137 )    | 83.370566 | 84.682575  |

### Benchmark 3

- Max samples: 4000
- Max sampling time: 4
- Security level: 80
- Precompute enabled: yes
- Hash type: sha1

| Operation      | Time (ms)              | Min (ms)  | Max (ms)  |
| -------------- | ---------------------- | --------- | --------- |
| Setup          | 9.206345 (±4.624189 )  | 5.194531  | 24.828495 |
| PublicParamsPP | 18.574201 (±0.013110 ) | 18.553068 | 18.610795 |
| ExtractP       | 2.425298 (±0.002073 )  | 2.420090  | 2.429446  |
| ExtractS       | 8.914725 (±0.006054 )  | 8.902148  | 8.931790  |
| Delegate       | 0.350210 (±0.007130 )  | 0.327395  | 0.361062  |
| DelVerify      | 3.189555 (±0.002362 )  | 3.183266  | 3.194636  |
| PKGen          | 0.165525 (±0.001130 )  | 0.163365  | 0.169441  |
| PSign          | 0.199791 (±0.005430 )  | 0.182005  | 0.206393  |
| SignVerify     | 5.744834 (±0.024774 )  | 5.707446  | 5.841770  |
| ImpPSign       | 1.298780 (±0.011952 )  | 1.249841  | 1.316911  |
| ImpSignVerify  | 5.817688 (±0.005254 )  | 5.807012  | 5.833503  |

### Benchmark 4

- Max samples: 4000
- Max sampling time: 4
- Security level: 128
- Precompute enabled: yes
- Hash type: sha256

| Operation      | Time (ms)                 | Min (ms)   | Max (ms)   |
| -------------- | ------------------------- | ---------- | ---------- |
| Setup          | 263.444268 (±203.154644 ) | 51.219608  | 576.610473 |
| PublicParamsPP | 146.099321 (±0.082385 )   | 146.004977 | 146.267850 |
| ExtractP       | 31.232197 (±0.025093 )    | 31.190866  | 31.286263  |
| ExtractS       | 66.683236 (±0.029906 )    | 66.629338  | 66.750302  |
| Delegate       | 1.930119 (±0.030784 )     | 1.832695   | 1.979722   |
| DelVerify      | 41.791100 (±0.078755 )    | 41.582306  | 41.915394  |
| PKGen          | 0.891503 (±0.001761 )     | 0.888511   | 0.895623   |
| PSign          | 1.075370 (±0.025364 )     | 0.997571   | 1.116830   |
| SignVerify     | 79.251704 (±0.200107 )    | 78.952166  | 79.621875  |
| ImpPSign       | 7.339721 (±0.086436 )     | 7.146421   | 7.524873   |
| ImpSignVerify  | 75.583828 (±0.199131 )    | 75.147146  | 75.959920  |
