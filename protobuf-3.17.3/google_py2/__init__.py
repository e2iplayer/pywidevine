try:
  __import__('pkg_resources').declare_namespace(__name__)
except ImportError:
  try:
    __path__ = __import__('pkgutil').extend_path(__path__, __name__)
  except ImportError:
    pass
