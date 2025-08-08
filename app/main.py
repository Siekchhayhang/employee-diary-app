# app/main.py
# Updated with all new features and routes.
from flask import Blueprint, render_template, flash, redirect, url_for, abort, make_response, g
from werkzeug.security import generate_password_hash
from .models import User, DiaryEntry
from mongoengine.errors import DoesNotExist
from .forms import DiaryEntryForm, ResetPasswordForm, UpdateUserRoleForm
from .auth import jwt_required
import io
import csv
import secrets
from functools import wraps

main = Blueprint('main', __name__)

# --- Role Decorators ---
def admin_required(f):
    @wraps(f)
    def decorated_function(*args, **kwargs):
        if not g.get('user') or g.user.role not in ['admin', 'superadmin']:
            abort(403)
        return f(*args, **kwargs)
    return decorated_function

def superadmin_required(f):
    @wraps(f)
    def decorated_function(*args, **kwargs):
        if not g.get('user') or g.user.role != 'superadmin':
            abort(403)
        return f(*args, **kwargs)
    return decorated_function

# --- Main Routes ---
@main.route('/')
def index():
    return render_template('index.html')

@main.route('/profile')
@jwt_required
def profile():
    entries = DiaryEntry.objects(author=g.user.id).order_by('-date_posted')
    return render_template('profile.html', user=g.user, entries=entries)

# --- Diary Entry Routes ---
@main.route('/diary/new', methods=['GET', 'POST'])
@jwt_required
def new_diary_entry():
    form = DiaryEntryForm()
    if form.validate_on_submit():
        entry = DiaryEntry(title=form.title.data, content=form.content.data, author=g.user.id)
        entry.save()
        flash('Your diary entry has been created!', 'success')
        return redirect(url_for('main.profile'))
    return render_template('create_entry.html', title='New Diary Entry', form=form)

@main.route('/diary/<entry_id>/edit', methods=['GET', 'POST'])
@jwt_required
def edit_diary_entry(entry_id):
    entry = DiaryEntry.objects(pk=entry_id).first_or_404()
    if entry.author.id != g.user.id:
        abort(403)
    form = DiaryEntryForm(obj=entry)
    if form.validate_on_submit():
        entry.title = form.title.data
        entry.content = form.content.data
        entry.save()
        flash('Your diary entry has been updated!', 'success')
        return redirect(url_for('main.profile'))
    return render_template('edit_entry.html', title='Edit Diary Entry', form=form, entry=entry)

@main.route('/diary/<entry_id>/delete', methods=['POST'])
@jwt_required
def delete_diary_entry(entry_id):
    entry = DiaryEntry.objects(pk=entry_id).first_or_404()
    if entry.author.id != g.user.id:
        abort(403)
    entry.delete()
    flash('Your diary entry has been deleted.', 'success')
    return redirect(url_for('main.profile'))

# --- Admin Panel Routes ---
@main.route('/admin')
@jwt_required
@admin_required
def admin_panel():
    users = User.objects().order_by('-created_at')
    return render_template('admin.html', users=users)

@main.route('/admin/user/<user_id>/edit', methods=['GET', 'POST'])
@jwt_required
@superadmin_required
def edit_user(user_id):
    user_to_edit = User.objects(pk=user_id).first_or_404()
    form = UpdateUserRoleForm(obj=user_to_edit)
    if form.validate_on_submit():
        user_to_edit.role = form.role.data
        user_to_edit.save()
        flash(f"Role for {user_to_edit.username} has been updated to '{user_to_edit.role}'.", 'success')
        return redirect(url_for('main.admin_panel'))
    return render_template('edit_user.html', title="Edit User", form=form, user=user_to_edit)

@main.route('/admin/user/<user_id>/reset_password', methods=['GET', 'POST'])
@jwt_required
@superadmin_required
def reset_password(user_id):
    user_to_reset = User.objects(pk=user_id).first_or_404()
    form = ResetPasswordForm()
    if form.validate_on_submit():
        hashed_password = generate_password_hash(form.password.data, method='pbkdf2:sha256')
        user_to_reset.password = hashed_password
        user_to_reset.session_token = secrets.token_hex(16)
        user_to_reset.save()
        flash(f"Password for {user_to_reset.username} has been reset successfully.", 'success')
        return redirect(url_for('main.edit_user', user_id=user_to_reset.id))
    return render_template('reset_password.html', title='Reset Password', form=form, user=user_to_reset)

@main.route('/admin/user/<user_id>/delete', methods=['POST'])
@jwt_required
@superadmin_required
def delete_user(user_id):
    user_to_delete = User.objects(pk=user_id).first_or_404()
    if user_to_delete.id == g.user.id:
        flash("You cannot delete your own account.", "danger")
        return redirect(url_for('main.admin_panel'))
    user_to_delete.delete()
    flash(f"User '{user_to_delete.username}' has been deleted.", "success")
    return redirect(url_for('main.admin_panel'))

# --- Reporting Routes ---
@main.route('/profile/report/download')
@jwt_required
def download_profile_report():
    entries = DiaryEntry.objects(author=g.user.id).order_by('-date_posted')
    si = io.StringIO()
    cw = csv.writer(si)
    header = ['Entry ID', 'Title', 'Date Posted', 'Content']
    cw.writerow(header)
    for entry in entries:
        cw.writerow([
            entry.id or "",
            entry.title or "",
            entry.date_posted.strftime('%Y-%m-%d %H:%M:%S') if entry.date_posted else "",
            entry.content or ""
        ])
    output = make_response(si.getvalue())
    output.headers["Content-Disposition"] = f"attachment; filename={g.user.username}_diary_report.csv"
    output.headers["Content-type"] = "text/csv"
    return output

@main.route('/admin/report/download')
@jwt_required
@admin_required
def download_report():
    entries = DiaryEntry.objects().order_by('-date_posted')
    si = io.StringIO()
    cw = csv.writer(si)
    header = ['Entry ID', 'Title', 'Date Posted', 'Author', 'Content']
    cw.writerow(header)
    for entry in entries:
        author_username = "Unknown"
        try:
            if entry.author:
                author_username = entry.author.username
        except DoesNotExist:
            author_username = "Deleted User"
        
        cw.writerow([
            entry.id or "",
            entry.title or "",
            entry.date_posted.strftime('%Y-%m-%d %H:%M:%S') if entry.date_posted else "",
            author_username,
            entry.content or ""
        ])
            
    output = make_response(si.getvalue())
    output.headers["Content-Disposition"] = "attachment; filename=employee_diary_report.csv"
    output.headers["Content-type"] = "text/csv"
    return output
