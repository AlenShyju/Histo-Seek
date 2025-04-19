🔗 Live Demo: https://histo-seek.onrender.com

# 📊 HISTO-SEEK

Histo-Seek is a powerful tool designed to extract, process, and analyze browsing history from popular web browsers such as Chrome, Firefox, and Edge. It helps users gain insights into their web activity, categorize visited websites, and identify browsing patterns.

## 🔍 Features

- ✅ Cross-browser support (Chrome, Firefox, Edge)
- 📅 View browsing history over specific date ranges
- 📁 Export history to CSV, JSON, or Excel
- 📊 Generate usage statistics and graphs
- 🧠 Categorize websites (Social Media, News, Education, etc.)
- 🕵️‍♂️ Privacy-first: all data is processed locally

## 📦 Installation

```bash
git clone https://github.com/your-username/browser-history-analyzer.git
cd browser-history-analyzer
pip install -r requirements.txt
```

> Make sure Python 3.7 or above is installed on your system.

## 🚀 Usage

```bash
python analyzer.py
```

Or use the graphical interface if included:

```bash
python gui.py
```

### Command Line Options

```bash
python analyzer.py --browser chrome --output csv --from "2025-01-01" --to "2025-01-31"
```

| Argument     | Description                         |
|--------------|-------------------------------------|
| `--browser`  | Select browser: `chrome`, `firefox`, `edge` |
| `--from`     | Start date in `YYYY-MM-DD` format   |
| `--to`       | End date in `YYYY-MM-DD` format     |
| `--output`   | Output format: `csv`, `json`, `xlsx`|

## 📈 Sample Output

- Total websites visited: 230
- Most visited domain: `www.google.com`
- Time spent on social media: 3h 20m
- Top 5 domains: Google, YouTube, StackOverflow, GitHub, Reddit

## 🔒 Privacy and Security

This tool does **not** upload or store any of your browsing data online. All processing is done **locally** on your machine.

## 🛠️ Built With

- Python
- SQLite
- Pandas
- Matplotlib / Plotly (for graphs)
- Tkinter or PyQt (optional GUI)

## 📁 Supported Platforms

- Windows
- macOS
- Linux

## 📚 Future Improvements

- Cloud backup integration
- Daily/weekly usage reports
- Anomaly detection (e.g., spike in unknown sites)

## 🤝 Contributing

Pull requests are welcome! For major changes, please open an issue first to discuss what you would like to change.

## 📄 License

This project is licensed under the [MIT License](LICENSE).

## 🙌 Acknowledgements

Thanks to the open-source community and developers of browser data extraction libraries like `browser-history`, `sqlite`, etc.

🙌 Author
Alen P Shyju
📫 https://www.linkedin.com/in/alen-p-shyju-/ | 🌐 https://alenshyju.vercel.app/ | ✉️ alenshyju27@gmail.com

---
