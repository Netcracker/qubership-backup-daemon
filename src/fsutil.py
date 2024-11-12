import os
from subprocess import *
import zipfile
import tarfile


def touch(filepath):
    open(filepath, "w").close()


def tail(filepath, lines):
    p = Popen("tail -n " + str(lines) + " " + filepath, shell=True, stdin=PIPE, stdout=PIPE, close_fds=True)
    stdin, stdout = p.stdin, p.stdout
    stdin.close()
    lines = stdout.readlines()
    stdout.close()
    return lines


def get_folder_size(dirpath):
    total_size = 0
    is_mountpoint = get_mounted_device(dirpath)
    if is_mountpoint:
        fs_stats = get_fs_space(dirpath)
        return fs_stats["total_space"] - fs_stats["free_space"]
    for dirpath, dirname, filenames in os.walk(dirpath):
        for f in filenames:
            fp = os.path.join(dirpath, f)
            total_size += os.path.getsize(fp)
    return total_size


def get_mount_point(pathname):
    """Get the mount point of the filesystem containing pathname"""
    pathname = os.path.normcase(os.path.realpath(pathname))
    parent_device = path_device = os.stat(pathname).st_dev
    mount_point = None
    while parent_device == path_device:
        mount_point = pathname
        pathname = os.path.dirname(pathname)
        if pathname == mount_point:
            break
        parent_device = os.stat(pathname).st_dev
    return mount_point


def get_mounted_device(pathname):
    """Get the device mounted at pathname"""
    # uses "/proc/mounts"
    pathname = os.path.normcase(pathname)  # might be unnecessary here
    try:
        with open("/proc/mounts", "r") as ifp:
            for line in ifp:
                fields = line.rstrip('\n').split()
                # note that line above assumes that
                # no mount points contain whitespace
                if fields[1] == pathname:
                    return fields[0]
    except EnvironmentError:
        pass
    return None  # explicit


def get_fs_space(pathname):
    """Get the free space, total space, free inodes and total inodes of the filesystem containing pathname"""

    stat = os.statvfs(pathname)
    return {"free_space": stat.f_bfree * stat.f_bsize,
            "total_space": stat.f_blocks * stat.f_bsize,
            "free_inodes": stat.f_favail,
            "total_inodes": stat.f_files}


def readenv(var):
    if var in os.environ:
        return os.environ[var]
    else:
        return None


def list_tar_archive(archive_name):
    if archive_name and tarfile.is_tarfile(archive_name):
        with tarfile.TarFile(archive_name, mode='r') as tf:
            return [info.name for info in tf.getmembers()]
    else:
        raise tarfile.TarError("Error while listing tar archive")


def list_zip_archive(archive_name):
    if archive_name and zipfile.is_zipfile(archive_name):
        with zipfile.ZipFile(archive_name, mode='r', allowZip64=True) as zf:
            return zf.namelist()
    else:
        raise zipfile.BadZipFile("Error while listing zip archive")


def list_archive(archive_name):
    ext = os.path.splitext(archive_name)[1].replace('.', '').lower()
    list_function = list_tar_archive if ext == 'tgz' else list_zip_archive
    return list_function(archive_name)

def rmtree(path):
    for root, dirs, files in os.walk(path, topdown=False):
            for name in files:
                os.remove(os.path.join(root, name))
            for name in dirs:
                os.rmdir(os.path.join(root, name))
    os.rmdir(path)