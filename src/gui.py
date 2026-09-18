import sys

from PySide6.QtWidgets import QApplication
from securestate.ui.main_window import MainWindow


def main():
    app = QApplication(sys.argv)
    app.setApplicationName("SecureState Lab")

    window = MainWindow()
    window.show()

    sys.exit(app.exec())


if __name__ == "__main__":
    main()
