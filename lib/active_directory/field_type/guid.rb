#-- license
#
#  Based on original code by Justin Mecham and James Hunt
#  at http://rubyforge.org/projects/activedirectory
#
# This program is free software: you can redistribute it and/or modify
# it under the terms of the GNU General Public License as published by
# the Free Software Foundation, either version 3 of the License, or
# (at your option) any later version.
#
# This program is distributed in the hope that it will be useful,
# but WITHOUT ANY WARRANTY; without even the implied warranty of
# MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
# GNU General Public License for more details.
#
# You should have received a copy of the GNU General Public License
# along with this program.  If not, see <http://www.gnu.org/licenses/>.
#
#++ license

module ActiveDirectory
  module FieldType
    class GUID
      #
      # Encodes a hex string into a GUID
      #
      def self.encode(hex_string)
        [hex_string].pack("H*")
      end

      #
      # Decodes a binary GUID as a hex string
      #
      def self.decode(binary)
         hex_guid = binary.unpack("H*").first.to_s
         guid = ""
         guid << hex_guid[6..7]
         guid << hex_guid[4..5]
         guid << hex_guid[2..3]
         guid << hex_guid[0..1]
         guid << "-"
         guid << hex_guid[10..11]
         guid << hex_guid[8..9]
         guid << "-"
         guid << hex_guid[14..15]
         guid << hex_guid[12..13]
         guid << "-"
         guid << hex_guid[16..19]
         guid << "-"
         guid << hex_guid[20..31]
         guid
      end
    end
  end
end