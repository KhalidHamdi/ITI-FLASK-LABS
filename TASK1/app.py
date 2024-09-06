from flask import Flask, render_template

app = Flask(__name__)

students = [
    {'id': 1, 'name': 'Khalid'},
    {'id': 2, 'name': 'Hamdi'},
    {'id': 3, 'name': 'Galal'},
]

@app.route('/')
def home():
    return render_template('index.html', students=students)

@app.route('/search/<int:id>')
def search(id):
    return render_template("search.html", students=students, studentId=id)

if __name__ == '__main__':
    app.run(debug=True)
