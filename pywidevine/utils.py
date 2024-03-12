from uuid import UUID

import sys

if sys.version_info.major == 3:
  def to_bytes(n, length, byteorder='big'):
    return n.to_bytes(length, byteorder)
else:
  def to_bytes(n, length, byteorder='big'):
    h = '%x' % n
    s = ('0'*(len(h) % 2) + h).zfill(length*2).decode('hex')
    return s if byteorder == 'big' else s[::-1]
    
class Pssh(object):
  """Defines a PSSH box and related functions."""

  def __init__(self, version, system_id, key_ids, pssh_data):
    """Parses a PSSH box from the given data.

    Args:
      version: The version number of the box
      system_id: A binary string of the System ID
      key_ids: An array of binary strings for the key IDs
      pssh_data: A binary string of the PSSH data
    """
    self.version = version
    self.system_id = system_id
    self.key_ids = key_ids or []
    self.pssh_data = pssh_data or ''

def to_code_point(value):
  if isinstance(value, int):
    return value
  return ord(value)

# https://github.com/shaka-project/shaka-packager/blob/main/packager/tools/pssh/pssh-box.py
class BinaryReader(object):
  """A helper class used to read binary data from an binary string."""

  def __init__(self, data, little_endian=False):
    self.data = data
    self.little_endian = little_endian
    self.position = 0

  def has_data(self):
    """Returns whether the reader has any data left to read."""
    return self.position < len(self.data)

  def read_bytes(self, count):
    """Reads the given number of bytes into an array."""
    if len(self.data) < self.position + count:
      raise Exception('Invalid PSSH box, not enough data')
    ret = self.data[self.position:self.position+count]
    self.position += count
    return ret

  def read_int(self, size):
    """Reads an integer of the given size (in bytes)."""
    data = self.read_bytes(size)
    ret = 0
    for i in range(0, size):
      if self.little_endian:
        ret |= (to_code_point(data[i]) << (8 * i))
      else:
        ret |= (to_code_point(data[i]) << (8 * (size - i - 1)))
    return ret

def parse_boxes(data):
  """Parses one or more PSSH boxes for the given binary data."""
  reader = BinaryReader(data, little_endian=False)
  boxes = []
  while reader.has_data():
    start = reader.position
    size = reader.read_int(4)

    box_type = reader.read_bytes(4)
    if box_type != b'pssh':
      raise Exception(
          'Invalid box type 0x%s, not \'pssh\'' % box_type.encode('hex'))

    version_and_flags = reader.read_int(4)
    version = version_and_flags >> 24
    if version > 1:
      raise Exception('Invalid PSSH version %d' % version)

    system_id = UUID(bytes = reader.read_bytes(16))

    key_ids = []
    if version == 1:
      count = reader.read_int(4)
      while count > 0:
        key = reader.read_bytes(16)
        key_ids.append(key)
        count -= 1

    pssh_data_size = reader.read_int(4)
    pssh_data = reader.read_bytes(pssh_data_size)

    if start + size != reader.position:
      raise Exception('Box size does not match size of data')

    pssh = Pssh(version, system_id, key_ids, pssh_data)
    boxes.append(pssh)
  return boxes
