from flask_wtf import FlaskForm
from wtforms import StringField, SubmitField, PasswordField
from wtforms.validators import DataRequired, Length


class NameForm(FlaskForm):
    name = StringField("Please add task name", validators=[DataRequired()])
    submit = SubmitField("Submit Name")


class AddressForm(FlaskForm):
    address = StringField("Please add/update address", validators=[DataRequired()])
    submit = SubmitField("Submit Address")


class RegisterForm(FlaskForm):
    username = StringField("Username",validators=[DataRequired()])
    password = PasswordField("Password (at least 6 characters)",validators=[DataRequired(),Length(min=6)])
    password_repeat = PasswordField("Confirm password (match the password field)",validators=[DataRequired(),Length(min=6)])
    submit = SubmitField("Register User")