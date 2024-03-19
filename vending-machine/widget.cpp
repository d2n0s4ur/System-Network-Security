#include "widget.h"
#include "ui_widget.h"
#include "QMessageBox"
#include "QString"

Widget::Widget(QWidget *parent)
    : QWidget(parent)
    , ui(new Ui::Widget)
{
    ui->setupUi(this);
    ui->pushButton_5->setEnabled(false);
    ui->pushButton_6->setEnabled(false);
    ui->pushButton_7->setEnabled(false);
}

Widget::~Widget()
{
    delete ui;
}

void Widget::changeMoney(int amount)
{
    money += amount;
    ui->lcdNumber->display(money);
    if (money >= 100)
        ui->pushButton_5->setEnabled(true);
    else
        ui->pushButton_5->setEnabled(false);
    if (money >= 150)
        ui->pushButton_6->setEnabled(true);
    else
        ui->pushButton_6->setEnabled(false);
    if (money >= 200)
        ui->pushButton_7->setEnabled(true);
    else
        ui->pushButton_7->setEnabled(false);
}

void Widget::on_pushButton_clicked()
{
    changeMoney(10);
}


void Widget::on_pushButton_2_clicked()
{
    changeMoney(50);
}


void Widget::on_pushButton_3_clicked()
{
    changeMoney(100);
}


void Widget::on_pushButton_4_clicked()
{
    changeMoney(500);
}


void Widget::on_pushButton_5_clicked()
{
    changeMoney(-100);
}


void Widget::on_pushButton_6_clicked()
{
    changeMoney(-150);
}


void Widget::on_pushButton_7_clicked()
{
    changeMoney(-200);
}


void Widget::on_pushButton_8_clicked()
{
    QMessageBox mb;
    int lastmoney = money;

    int n4 = lastmoney / 500;
    lastmoney %= 500;
    int n3 = lastmoney / 100;
    lastmoney %= 100;
    int n2 = lastmoney / 50;
    lastmoney %= 50;
    int n1 = lastmoney / 10;

    QString str = QString("10: %1, 50: %2, 100: %3, 500: %4").arg(n1).arg(n2).arg(n3).arg(n4);
    changeMoney(-money);

    mb.information(nullptr, "RESET!!", str);
}

