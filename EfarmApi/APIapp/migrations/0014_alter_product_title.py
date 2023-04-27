# Generated by Django 3.2.4 on 2023-04-27 05:51

from django.db import migrations, models


class Migration(migrations.Migration):

    dependencies = [
        ('APIapp', '0013_checkout_feedback'),
    ]

    operations = [
        migrations.AlterField(
            model_name='product',
            name='title',
            field=models.CharField(choices=[('Apple', 'Apple'), ('Banana', 'Banana'), ('Black Berries', 'Black Berries'), ('Blue Berries', 'Blue Berries'), ('Brinjal', 'Brinjal'), ('Bitter Gourd', 'Bitter Gourd'), ('Capsicum', 'Capsicum'), ('Cabbage', 'Cabbage'), ('Chili', 'Chili'), ('Cherries', 'Cherries'), ('Custard Apple', 'Custard Apple'), ('cluster Beans', 'cluster Beans'), ('Elephant Tusk Okra', 'Elephant Tusk Okra'), ('Flat Beans', 'Flat Beans'), ('Ginger', 'Ginger'), ('Grapes', 'Grapes'), ('Guava', 'Guava'), ('malabar Cucumber', 'malabar Cucumber'), ('Mango', 'Mango'), ('Onion', 'Onion'), ('Okra', 'Okra'), ('Orange', 'Orange'), ('Pine Apple', 'Pine Apple'), ('Carrot', 'Carrot'), ('Pear', 'Pear'), ('Plumps', 'Plumps'), ('Papaya', 'Papaya'), ('PumpKins', 'PumpKins'), ('Pigeon Pea', 'Pigeon Pea'), ('Potato', 'Potato'), ('Snake Cucumber', 'Snake Cucumber'), ('Tarmeric', 'Tarmeric'), ('Water Melon', 'Water Melon'), ('Water Spinach', 'Water Spinach')], max_length=50),
        ),
    ]
