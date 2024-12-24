import matplotlib.pyplot as plt

categories = ['Work', 'Personal', 'Others']
total_tasks = [10, 5, 3]
done_tasks = [7, 3, 2]

plt.figure(figsize=(8, 4))
plt.subplot(1, 2, 1)
plt.pie(total_tasks, labels=categories, autopct='%1.1f%%', startangle=140)
plt.title("Total Tasks by Category")

plt.subplot(1, 2, 2)
plt.pie(done_tasks, labels=categories, autopct='%1.1f%%', startangle=140)
plt.title("Completed Tasks by Category")

plt.savefig('static/test_chart.png')
plt.show()
