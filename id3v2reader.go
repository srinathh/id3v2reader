//
package id3v2reader

import (
	//"bytes"
	"bytes"
	"errors"
	"fmt"
	"io"
	"regexp"
	"unicode/utf16"
)

// ID3Frames contain the data extracted from each frame. Data extraction functions are bound to ID3Frame to give human readable representations
// Since flag handling differs between ID3 versions, each frame has 1 byte of version info appended
type ID3Frame struct {
	FrameID               string
	Length                uint32
	Compression           bool
	Encryption            bool
	Unsynchronisation     bool
	Data_Length_Indicator bool
	Data                  []byte
}

// An ID3Tag type is an alias for a dictionary mapping FrameID with an ID3Frame. Though ID3 tags can contain theoritically multiple non
// text-frames of the same type (text-frames are restricted) as per standard, a simplifying assumption of 1 to 1 mapping between FrameID
// and the frame data is used here. ReadID3 function reads only the very first occurance of any FrameID
type ID3Tag []ID3Frame

func decodeISO88591(buf []byte) string {
	end_of_string := bytes.IndexByte(buf, 0)
	if end_of_string == -1 {
		end_of_string = len(buf)
	}
	uni_buf := make([]rune, end_of_string)
	for j := 0; j < end_of_string; j++ {
		uni_buf[j] = rune(buf[j])
	}
	return string(uni_buf)
}

func decodeUTF8(buf []byte) string {
	end_of_string := bytes.IndexByte(buf, 0)
	if end_of_string == -1 {
		end_of_string = len(buf)
	}
	return string(buf[0:end_of_string])
}

func decodeUTF16(buf []byte, bigendian bool) string {
	maxchars := len(buf) / 2
	utf16buf := make([]uint16, maxchars)

	for j := 0; j < maxchars; j++ {
		if buf[j*2] == 0 && buf[j*2+1] == 0 {
			utf16buf = utf16buf[0:j]
			break
		}
		if bigendian {
			utf16buf[j] = uint16(buf[j*2])<<8 | uint16(buf[j*2+1])
		} else {
			utf16buf[j] = uint16(buf[j*2+1])<<8 | uint16(buf[j*2])
		}
	}
	return string(utf16.Decode(utf16buf))
}

func decodetext(encoding byte, data []byte) (string, error) {
	switch encoding {
	case 0:
		return decodeISO88591(data), nil
	case 1:
		if data[0] == 0xFE && data[1] == 0xFF {
			return decodeUTF16(data[2:len(data)], true), nil
		} else if data[0] == 0xFF && data[1] == 0xFE {
			return decodeUTF16(data[2:len(data)], false), nil
		}
	case 2:
		return decodeUTF16(data, true), nil
	case 3:
		return decodeUTF8(data), nil
	}
	return "", errors.New("Unable to parse text frame")
}

func read_bytes(rd io.Reader, length uint32) ([]byte, error) {
	buf := make([]byte, length)
	n, _ := rd.Read(buf)
	if uint32(n) == length {
		return buf, nil
	}
	return nil, errors.New(fmt.Sprintf("Could not read %v bytes", length))
}

func read_validated(rd io.Reader, length uint32, match_pattern string) ([]byte, error) {
	if buf, err := read_bytes(rd, length); err != nil {
		return nil, err
	} else {
		valid, rxperr := regexp.Match(match_pattern, buf)
		if rxperr == nil && valid {
			return buf, nil
		}
	}
	return nil, errors.New(fmt.Sprintf("Could not find a match to the expression %s\n", match_pattern))
}

func convert_synchsafe_int(buf []byte) (uint32, error) {
	retval := uint32(0)
	valid, rxperr := regexp.Match("[\x00-\x7F]{4}", buf)
	if rxperr == nil && valid {
		for j := 0; j < 4; j++ {
			retval = retval | (uint32(0x7F&buf[j]) << uint(7*(3-j)))
		}
		return retval, nil
	} else {
		return retval, errors.New("4 bytes are needed to convert a synchsafe uint")
	}
}

func convert_regular_int(buf []byte) (uint32, error) {
	if len(buf) != 4 {
		return uint32(0), errors.New("4 bytes are needed to convert a regular uint")
	}
	return uint32(buf[0]<<24 | buf[1]<<16 | buf[2]<<8 | buf[3]), nil
}

func read_bitbool(b byte) (bit7, bit6, bit5, bit4, bit3, bit2, bit1, bit0 bool) {
	retbools := make([]bool, 8)
	for j := uint(0); j < 8; j++ {
		if b&1<<j != 0 {
			retbools[j] = true
		} else {
			retbools[j] = false
		}
	}
	return retbools[7], retbools[6], retbools[5], retbools[4], retbools[3], retbools[2], retbools[1], retbools[0]
}

func ReadID3(rd io.Reader) (ID3Tag, error) {

	var tag_ver byte
	var header_unsync, header_has_ext, header_expt bool
	var tag_length, data_read_ctr uint32

	var rettag = make(ID3Tag, 1)

	//read and validate the ID3 tag header
	if header, header_err := read_validated(rd, 10, "ID3[\x03\x04]..[\x00-\x7F]{4}"); header_err != nil {
		return nil, errors.New("Did not find supported ID3v2 header at start of file")
	} else {
		tag_ver = header[3]
		header_unsync, header_has_ext, header_expt, _, _, _, _, _ = read_bitbool(header[5:6][0])
		tag_length, _ = convert_synchsafe_int(header[6:10])

		if header_unsync || header_has_ext || header_expt {
			return nil, errors.New(fmt.Sprintf("Tag has one or more unsupported features: Unsynchronization:%v Extended Header:%v Experimental:%v", header_unsync, header_has_ext, header_expt))
		}

		data_read_ctr = 0

		for data_read_ctr < tag_length {
			if frameheader, frameheader_err := read_validated(rd, 10, "[A-Z0-9]{4}......"); frameheader_err != nil {
				break
			} else {
				curframe := new(ID3Frame)
				curframe.FrameID = string(frameheader[0:4])
				if tag_ver == 3 {
					curframe.Length, _ = convert_regular_int(frameheader[4:8])
					curframe.Compression, curframe.Encryption, _, _, _, _, _, _ = read_bitbool(frameheader[9])
					curframe.Data_Length_Indicator = false
					curframe.Unsynchronisation = false
				} else { //tag version is 4 already checked for only 3 & 4 match before getting here
					curframe.Length, _ = convert_synchsafe_int(frameheader[4:8])
					_, _, _, _, curframe.Compression, curframe.Encryption, curframe.Unsynchronisation, curframe.Data_Length_Indicator = read_bitbool(frameheader[9])
				}

				if frdata, dterr := read_bytes(rd, curframe.Length); dterr != nil {
					break
				} else {
					curframe.Data = frdata
					data_read_ctr += curframe.Length + 10
					rettag = append(rettag, *curframe)
					//rettag[curframe.FrameID] = *curframe
				}
			}
		}
	}

	return rettag, nil
}

//gets data from each of the frames referred to by a tag title
func (id3tag ID3Tag) GetTagData(frameid string) [][]byte {
	ret := make([][]byte, 0)
	for _, id3frame := range id3tag {
		if id3frame.FrameID == frameid {
			if id3frame.Compression || id3frame.Encryption || id3frame.Unsynchronisation {
				//tk code to handle compression, unsynchronization
			} else {
				ret = append(ret, id3frame.Data)
			}
		}
	}
	return ret
}

func (id3tag ID3Tag) GetTextFrameData(frameid string) (string, error) {
	framedatas := id3tag.GetTagData(frameid)
	if len(framedatas) > 0 {
		text, err := decodetext(framedatas[0][0], framedatas[0][1:len(framedatas[0])])
		return text, err
	}
	return "", errors.New(fmt.Sprintf("No such frame %v found in the taglist", frameid))
}

func (id3tag ID3Tag) GetTitle() (string, error) {
	txt, err := id3tag.GetTextFrameData("TIT2")
	return txt, err
}

func (id3tag ID3Tag) GetAlbum() (string, error) {
	txt, err := id3tag.GetTextFrameData("TALB")
	return txt, err
}

func (id3tag ID3Tag) GetArtist() (string, error) {
	txt, err := id3tag.GetTextFrameData("TPE1")
	return txt, err
}

func (id3tag ID3Tag) GetComposer() (string, error) {
	txt, err := id3tag.GetTextFrameData("TCOM")
	return txt, err
}

func (id3tag ID3Tag) GetCoverPic() ([]byte, error) {
	framedatas := id3tag.GetTagData("APIC")
	for _, framedata := range framedatas {
		text_encoding := framedata[0]
		if mime_type_end := bytes.IndexByte(framedata[1:len(framedata)], 0); mime_type_end != -1 && mime_type_end+3 < len(framedata) {
			if pictype := framedata[mime_type_end+2]; pictype == 3 || pictype == 4 {
				if text_encoding == 0 || text_encoding == 3 {
					desc_end := bytes.IndexByte(framedata[mime_type_end+3:len(framedata)], 0)
					return framedata[desc_end+1 : len(framedata)], nil
				} else if text_encoding == 1 || text_encoding == 2 {
					desc_end := bytes.Index(framedata[mime_type_end+3:len(framedata)], []byte{0, 0})
					return framedata[desc_end+2 : len(framedata)], nil
				}
			}
		}
	}
	return []byte{}, errors.New("No cover pic found")
}
