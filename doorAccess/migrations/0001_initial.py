# Generated by Django 2.0.5 on 2018-07-15 10:04

from django.conf import settings
from django.db import migrations, models
import django.db.models.deletion


class Migration(migrations.Migration):

    initial = True

    dependencies = [
        ('auth', '0009_alter_user_last_name_max_length'),
    ]

    operations = [
        migrations.CreateModel(
            name='UserProfile',
            fields=[
                ('id', models.AutoField(auto_created=True, primary_key=True, serialize=False, verbose_name='ID')),
                ('password', models.CharField(max_length=128, verbose_name='password')),
                ('last_login', models.DateTimeField(blank=True, null=True, verbose_name='last login')),
                ('is_superuser', models.BooleanField(default=False, help_text='Designates that this user has all permissions without explicitly assigning them.', verbose_name='superuser status')),
                ('email', models.EmailField(max_length=255, unique=True)),
                ('name', models.CharField(max_length=255)),
                ('is_active', models.BooleanField(default=True)),
                ('is_staff', models.BooleanField(default=False)),
                ('nfc_tag_list', models.TextField()),
                ('nfc_tag_list_group', models.TextField()),
                ('groups', models.ManyToManyField(blank=True, help_text='The groups this user belongs to. A user will get all permissions granted to each of their groups.', related_name='user_set', related_query_name='user', to='auth.Group', verbose_name='groups')),
                ('user_permissions', models.ManyToManyField(blank=True, help_text='Specific permissions for this user.', related_name='user_set', related_query_name='user', to='auth.Permission', verbose_name='user permissions')),
            ],
            options={
                'abstract': False,
            },
        ),
        migrations.CreateModel(
            name='DoorNfcTagModel',
            fields=[
                ('id', models.AutoField(auto_created=True, primary_key=True, serialize=False, verbose_name='ID')),
                ('door_name', models.CharField(max_length=15)),
                ('nfc_tag', models.CharField(max_length=255)),
            ],
        ),
        migrations.CreateModel(
            name='NfcDACPhase1',
            fields=[
                ('id', models.AutoField(auto_created=True, primary_key=True, serialize=False, verbose_name='ID')),
                ('userKeys', models.CharField(max_length=7)),
            ],
        ),
        migrations.CreateModel(
            name='NfcDACPhase2',
            fields=[
                ('id', models.AutoField(auto_created=True, primary_key=True, serialize=False, verbose_name='ID')),
                ('userKeys', models.CharField(max_length=7)),
                ('keyHash', models.CharField(max_length=32)),
                ('TDAT2', models.CharField(max_length=32)),
            ],
        ),
        migrations.CreateModel(
            name='NfcDACPhase3',
            fields=[
                ('id', models.AutoField(auto_created=True, primary_key=True, serialize=False, verbose_name='ID')),
                ('userKeys', models.CharField(max_length=7)),
                ('aesEncryptedNfcPw', models.CharField(max_length=16)),
                ('aesSalt', models.CharField(max_length=16)),
                ('TDAT3', models.CharField(max_length=32)),
            ],
        ),
        migrations.CreateModel(
            name='NfcDoor',
            fields=[
                ('id', models.AutoField(auto_created=True, primary_key=True, serialize=False, verbose_name='ID')),
                ('nameOfDoor', models.CharField(default='door with no Name', max_length=255)),
                ('doorUUID', models.CharField(default='ZkVJT0H7hHlmMD6a', max_length=16)),
            ],
        ),
        migrations.CreateModel(
            name='NfcDoorGroup',
            fields=[
                ('id', models.AutoField(auto_created=True, primary_key=True, serialize=False, verbose_name='ID')),
                ('nameOfDoorGroup', models.CharField(default='group with no name', max_length=255)),
                ('listOfDoors', models.ManyToManyField(related_name='listOfDoors_NfcDoorGroup', to='doorAccess.NfcDoor')),
            ],
        ),
        migrations.CreateModel(
            name='NfcKey',
            fields=[
                ('id', models.AutoField(auto_created=True, primary_key=True, serialize=False, verbose_name='ID')),
                ('keyName', models.CharField(default='key with no name', max_length=255)),
                ('keyUUID', models.CharField(default='0KtuaSR', max_length=7)),
                ('keyUTID', models.CharField(default='ICYBAz8gXgGaTgToHpCcJRHHPKpJhbE4', max_length=32)),
                ('AESEncryptKey', models.CharField(default='tieK6JhZ1MPeaMG4', max_length=32)),
                ('accesTrue', models.CharField(default='CVnuRZjyS3qCHGta78GT01T6uV1IZstQ', max_length=32)),
            ],
        ),
        migrations.CreateModel(
            name='NfcListOfUsers',
            fields=[
                ('id', models.AutoField(auto_created=True, primary_key=True, serialize=False, verbose_name='ID')),
                ('userName', models.CharField(max_length=255)),
                ('TDAT', models.CharField(default='WUjZ1gk0nldaPlUt', max_length=32)),
                ('accessingUUID', models.CharField(default='vQZMfe8', max_length=7)),
                ('accesingUDID', models.CharField(default='vGjnL0eZVYpnqO2H', max_length=16)),
                ('encryptionKey', models.CharField(default='X5jUQOPYtWOLyjj5', max_length=16)),
                ('encryptionSalt', models.CharField(default='ulFmONot45piNIjl', max_length=16)),
                ('timeStamp', models.DateTimeField(auto_now=True)),
                ('listOfDoorGroups', models.ManyToManyField(related_name='DoorGroup_NfcListOfUsers', to='doorAccess.NfcDoorGroup')),
                ('listOfDoors', models.ManyToManyField(related_name='ListOfDoors_NfcListOfUsers', to='doorAccess.NfcDoor')),
                ('userKeys', models.ManyToManyField(related_name='ListOfKeys_NfcListOfUsers', to='doorAccess.NfcKey')),
            ],
        ),
        migrations.CreateModel(
            name='ProfileFeedItem',
            fields=[
                ('id', models.AutoField(auto_created=True, primary_key=True, serialize=False, verbose_name='ID')),
                ('status_text', models.CharField(max_length=255)),
                ('created_on', models.DateTimeField(auto_now_add=True)),
                ('user_profile', models.ForeignKey(on_delete=django.db.models.deletion.CASCADE, to=settings.AUTH_USER_MODEL)),
            ],
        ),
    ]
