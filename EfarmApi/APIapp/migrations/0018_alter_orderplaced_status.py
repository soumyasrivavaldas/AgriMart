# Generated by Django 3.2.4 on 2023-05-03 05:05

from django.db import migrations, models


class Migration(migrations.Migration):

    dependencies = [
        ('APIapp', '0017_alter_orderplaced_status'),
    ]

    operations = [
        migrations.AlterField(
            model_name='orderplaced',
            name='status',
            field=models.CharField(choices=[('Accepted', 'Accepted'), ('Packed', 'Packed'), ('On the way', 'On the way'), ('Dispached', 'Dispached'), ('Delivered', 'Delevered'), ('Cancle', 'Cancle')], default='Pending', max_length=50),
        ),
    ]
